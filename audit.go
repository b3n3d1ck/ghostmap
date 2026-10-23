package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Weakness is one passive security finding with how to fix it.
type Weakness struct {
	Severity string `json:"severity"` // TINGGI, SEDANG, RENDAH
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

// PageFlag marks something notable on a page we already fetched during crawl:
// a login form, or content that matches a known webshell UI.
type PageFlag struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // login, webshell
	Note string `json:"note,omitempty"`
}

// ---- content detectors (run only on pages the crawl already fetched) ----

var (
	reLoginForm = regexp.MustCompile(`(?i)<input[^>]+type=["']password["']|name=["']pass(?:word)?["']`)
	reDirList   = regexp.MustCompile(`(?i)<title>\s*index of /|>\s*Parent Directory\s*<`)

	// distinctive strings from known webshell interfaces. A page that is served
	// publicly and contains these is almost certainly a planted shell.
	reShellUI = regexp.MustCompile(`(?i)c99shell|r57shell|b374k|filesman|wso\s*\d|wsoshell|indoxploit|alfa team|p0wny|<title>[^<]*\bshell\b|\$auth_pass|uname -a</`)
)

// ---- header / cookie / version audit (from the root response) ----

var headerFix = map[string]struct{ sev, fix string }{
	"Content-Security-Policy":   {"SEDANG", "Set header Content-Security-Policy; mulai dari `default-src 'self'` lalu longgarkan seperlunya."},
	"Strict-Transport-Security": {"SEDANG", "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains` supaya browser memaksa HTTPS."},
	"X-Frame-Options":           {"RENDAH", "Set `X-Frame-Options: SAMEORIGIN` (atau `frame-ancestors` di CSP) untuk cegah clickjacking."},
	"X-Content-Type-Options":    {"RENDAH", "Set `X-Content-Type-Options: nosniff` agar browser tidak menebak tipe konten."},
	"Referrer-Policy":           {"RENDAH", "Set `Referrer-Policy: strict-origin-when-cross-origin`."},
	"Permissions-Policy":        {"RENDAH", "Batasi fitur browser lewat `Permissions-Policy`, mis. `geolocation=(), camera=()`."},
}

func auditHeaders(r *response) []Weakness {
	var out []Weakness
	for _, h := range missingSecurityHeaders(r) {
		f := headerFix[h]
		out = append(out, Weakness{
			Severity: f.sev,
			Title:    "Header keamanan hilang: " + h,
			Fix:      f.fix,
		})
	}
	return out
}

func auditCookies(r *response) []Weakness {
	var out []Weakness
	for _, raw := range r.headers["Set-Cookie"] {
		name := raw
		if i := strings.IndexByte(raw, '='); i >= 0 {
			name = raw[:i]
		}
		low := strings.ToLower(raw)
		var missing []string
		if !strings.Contains(low, "secure") {
			missing = append(missing, "Secure")
		}
		if !strings.Contains(low, "httponly") {
			missing = append(missing, "HttpOnly")
		}
		if !strings.Contains(low, "samesite") {
			missing = append(missing, "SameSite")
		}
		if len(missing) == 0 {
			continue
		}
		sev := "RENDAH"
		if strIn(missing, "HttpOnly") || strIn(missing, "Secure") {
			sev = "SEDANG"
		}
		out = append(out, Weakness{
			Severity: sev,
			Title:    "Cookie `" + strings.TrimSpace(name) + "` kurang atribut: " + strings.Join(missing, ", "),
			Fix:      "Tambahkan `Secure; HttpOnly; SameSite=Lax` pada cookie, terutama cookie sesi.",
		})
	}
	return out
}

func auditVersion(r *response) []Weakness {
	var out []Weakness
	reHasVer := regexp.MustCompile(`\d`)
	if v := r.headers.Get("Server"); v != "" && reHasVer.MatchString(v) {
		out = append(out, Weakness{
			Severity: "RENDAH",
			Title:    "Versi server terekspos di header",
			Detail:   "Server: " + v,
			Fix:      "Sembunyikan versi: `server_tokens off;` (Nginx) atau `ServerTokens Prod` (Apache).",
		})
	}
	if v := r.headers.Get("X-Powered-By"); v != "" {
		out = append(out, Weakness{
			Severity: "RENDAH",
			Title:    "Teknologi backend terekspos (X-Powered-By)",
			Detail:   "X-Powered-By: " + v,
			Fix:      "Matikan header: `expose_php = Off` di php.ini, atau hapus header di reverse proxy.",
		})
	}
	return out
}

// ---- transport: TLS certificate + HTTP->HTTPS redirect ----

func (s *scanner) auditTransport() {
	host := s.base.Host

	if s.base.Scheme == "https" {
		hp := host
		if !strings.Contains(hp, ":") {
			hp += ":443"
		}
		d := &net.Dialer{Timeout: 8 * time.Second}
		if conn, err := tls.DialWithDialer(d, "tcp", hp, &tls.Config{InsecureSkipVerify: true}); err == nil {
			cs := conn.ConnectionState()
			conn.Close()
			if len(cs.PeerCertificates) > 0 {
				cert := cs.PeerCertificates[0]
				days := int(time.Until(cert.NotAfter).Hours() / 24)
				switch {
				case days < 0:
					s.addWeak(Weakness{"TINGGI", "Sertifikat TLS sudah kedaluwarsa",
						"kedaluwarsa " + cert.NotAfter.Format("2006-01-02"),
						"Perbarui sertifikat segera (mis. certbot renew)."})
				case days < 14:
					s.addWeak(Weakness{"SEDANG", fmt.Sprintf("Sertifikat TLS hampir kedaluwarsa (%d hari lagi)", days),
						"berlaku sampai " + cert.NotAfter.Format("2006-01-02"),
						"Perbarui sertifikat sebelum habis; otomatiskan dengan certbot."})
				}
			}
			if cs.Version < tls.VersionTLS12 {
				s.addWeak(Weakness{"SEDANG", "Server menerima versi TLS lama (< 1.2)", "",
					"Nonaktifkan TLS 1.0/1.1, hanya izinkan TLS 1.2 dan 1.3."})
			}
		}
	}

	// did http:// redirect to https?
	if r, err := s.cl.get("http://" + host + "/"); err == nil {
		loc := strings.ToLower(r.location)
		redirected := r.status >= 300 && r.status < 400 && strings.HasPrefix(loc, "https://")
		if !redirected {
			s.addWeak(Weakness{"SEDANG", "HTTP tidak dialihkan ke HTTPS",
				fmt.Sprintf("http://%s/ menjawab status %d tanpa redirect ke https", host, r.status),
				"Paksa redirect 301 dari HTTP ke HTTPS, lalu aktifkan HSTS."})
		}
	}
}

// ---- helpers wired into the scanner ----

func (s *scanner) addWeak(w Weakness) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.weaknesses {
		if e.Title == w.Title {
			return
		}
	}
	s.weaknesses = append(s.weaknesses, w)
}

func (s *scanner) addFlag(path, kind, note string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.pageFlags {
		if e.Path == path && e.Kind == kind {
			return
		}
	}
	s.pageFlags = append(s.pageFlags, PageFlag{Path: path, Kind: kind, Note: note})
}

// checkContent inspects a body we already downloaded; it issues no new request.
func (s *scanner) checkContent(path string, body []byte) {
	if reShellUI.Match(body) {
		s.addFlag(path, "webshell", "cocok dengan tampilan webshell yang dikenal — periksa manual segera")
	}
	if reLoginForm.Match(body) {
		s.addFlag(path, "login", "halaman memuat form login")
	}
	if reDirList.Match(body) {
		s.addWeak(Weakness{"SEDANG", "Directory listing menyala di " + path, "",
			"Matikan auto-index: `autoindex off;` (Nginx) atau `Options -Indexes` (Apache)."})
	}
}

func strIn(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
