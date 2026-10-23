package main

import (
	"regexp"
	"strings"
)

// sensitive files worth checking, with a content signature so we only flag a
// real exposure (not a styled 200 "not found" page).
type sensitiveFile struct {
	path string
	sig  *regexp.Regexp
	risk string
}

var sensitiveFiles = []sensitiveFile{
	{"/.env", regexp.MustCompile(`(?i)APP_KEY|DB_(HOST|PASSWORD|DATABASE)|SECRET|MAIL_`), "File .env berisi kredensial"},
	{"/.git/config", regexp.MustCompile(`(?i)\[core\]|\[remote`), "Folder .git terekspos, kode sumber bisa diunduh"},
	{"/.git/HEAD", regexp.MustCompile(`(?i)ref:\s*refs/`), "Folder .git terekspos"},
	{"/.svn/entries", regexp.MustCompile(`(?i)dir|\d+`), "Folder .svn terekspos"},
	{"/.DS_Store", regexp.MustCompile(`Bud1|\x00\x00\x00`), "Daftar file folder bocor (.DS_Store)"},
	{"/phpinfo.php", regexp.MustCompile(`(?i)phpinfo\(\)|PHP Version`), "phpinfo() membocorkan konfigurasi server"},
	{"/.env.bak", regexp.MustCompile(`(?i)APP_KEY|DB_`), "Cadangan .env terekspos"},
	{"/.env.local", regexp.MustCompile(`(?i)APP_KEY|DB_|SECRET`), "File .env.local terekspos"},
	{"/config.php.bak", regexp.MustCompile(`(?i)<\?php|define\(|password`), "Cadangan config terekspos"},
	{"/wp-config.php.bak", regexp.MustCompile(`(?i)DB_PASSWORD|DB_NAME`), "Cadangan wp-config terekspos"},
	{"/backup.zip", regexp.MustCompile(`^PK\x03\x04`), "File backup bisa diunduh"},
	{"/backup.sql", regexp.MustCompile(`(?i)CREATE TABLE|INSERT INTO`), "Dump database terekspos"},
	{"/dump.sql", regexp.MustCompile(`(?i)CREATE TABLE|INSERT INTO`), "Dump database terekspos"},
	{"/docker-compose.yml", regexp.MustCompile(`(?i)services:|image:`), "docker-compose membocorkan arsitektur & secret"},
	{"/.aws/credentials", regexp.MustCompile(`(?i)aws_access_key_id`), "Kredensial AWS terekspos"},
	{"/server-status", regexp.MustCompile(`(?i)Apache Server Status|Scoreboard`), "server-status membocorkan request & IP"},
	{"/.htpasswd", regexp.MustCompile(`:\$|:[A-Za-z0-9./]{13}`), "File .htpasswd (hash password) terekspos"},
}

// fingerprint returns technologies detected from headers, cookies, and body.
func fingerprint(r *response) []string {
	set := map[string]bool{}
	add := func(s string) { set[s] = true }

	if v := r.headers.Get("Server"); v != "" {
		add("Server: " + v)
	}
	if v := r.headers.Get("X-Powered-By"); v != "" {
		add("X-Powered-By: " + v)
	}
	if v := r.headers.Get("X-AspNet-Version"); v != "" {
		add("ASP.NET " + v)
	}
	if v := r.headers.Get("X-Generator"); v != "" {
		add(v)
	}

	cookies := strings.ToLower(strings.Join(r.headers["Set-Cookie"], " "))
	for frag, tech := range map[string]string{
		"laravel_session": "Laravel", "phpsessid": "PHP", "connect.sid": "Express/Node",
		"jsessionid": "Java", "csrftoken": "Django", "sessionid": "Django",
		"ci_session": "CodeIgniter", "wordpress_": "WordPress", "asp.net": "ASP.NET",
	} {
		if strings.Contains(cookies, frag) {
			add(tech)
		}
	}

	body := strings.ToLower(string(r.body))
	for frag, tech := range map[string]string{
		"/wp-content/": "WordPress", "/wp-includes/": "WordPress", "cdn.shopify": "Shopify",
		"__next_data__": "Next.js", "data-reactroot": "React", "ng-version": "Angular",
		"/_nuxt/": "Nuxt.js", "drupal-settings-json": "Drupal", "joomla": "Joomla",
	} {
		if strings.Contains(body, frag) {
			add(tech)
		}
	}
	if m := regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)`).FindStringSubmatch(string(r.body)); m != nil {
		add("generator: " + m[1])
	}

	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

var securityHeaders = []struct{ key, label string }{
	{"content-security-policy", "Content-Security-Policy"},
	{"strict-transport-security", "Strict-Transport-Security"},
	{"x-frame-options", "X-Frame-Options"},
	{"x-content-type-options", "X-Content-Type-Options"},
	{"referrer-policy", "Referrer-Policy"},
	{"permissions-policy", "Permissions-Policy"},
}

func missingSecurityHeaders(r *response) []string {
	var out []string
	for _, h := range securityHeaders {
		if r.headers.Get(h.key) == "" {
			out = append(out, h.label)
		}
	}
	return out
}
