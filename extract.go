package main

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

	// href/src/action attributes in HTML
	reAttr = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#\s>]+)`)

	// endpoints/paths referenced inside JavaScript (linkfinder-style, trimmed down)
	reJS = regexp.MustCompile(`(?:"|'|` + "`" + `)(` +
		`(?:https?:)?//[a-zA-Z0-9._\-]+/[a-zA-Z0-9._~:/?#\[\]@!$&()*+,;=%\-]{1,}` + // absolute urls
		`|/[a-zA-Z0-9._\-/]{1,}(?:\.(?:php|aspx?|jsp|json|js|do|action|html?|xml|txt|cgi|pl|py|rb)|/)[a-zA-Z0-9._~:/?#\[\]@!$&()*+,;=%\-]{0,}` + // rooted paths w/ ext or trailing slash
		`|/api/[a-zA-Z0-9._\-/]{1,}` + // api routes
		`)(?:"|'|` + "`" + `)`)

	// paths listed in robots.txt
	reRobots  = regexp.MustCompile(`(?im)^\s*(?:dis)?allow\s*:\s*(\S+)`)
	reSitemap = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)`)
)

// sameHostPath resolves ref against base and returns the path if it is on the
// same host (or relative). Returns "" otherwise.
func sameHostPath(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	low := strings.ToLower(ref)
	for _, bad := range []string{"data:", "mailto:", "javascript:", "tel:", "#"} {
		if strings.HasPrefix(low, bad) {
			return ""
		}
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(u)
	if abs.Host != base.Host {
		return ""
	}
	p := abs.EscapedPath()
	if p == "" {
		p = "/"
	}
	if abs.RawQuery != "" {
		p += "?" + abs.RawQuery
	}
	return p
}

// extractFromHTML pulls same-host paths out of an HTML body.
func extractFromHTML(base *url.URL, body []byte) []string {
	var out []string
	for _, m := range reAttr.FindAllSubmatch(body, -1) {
		if p := sameHostPath(base, string(m[1])); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// extractFromJS pulls endpoints/paths referenced inside a JS file.
func extractFromJS(base *url.URL, body []byte) []string {
	var out []string
	for _, m := range reJS.FindAllSubmatch(body, -1) {
		if p := sameHostPath(base, string(m[1])); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func extractRobots(base *url.URL, body []byte) (paths []string, sitemaps []string) {
	for _, m := range reRobots.FindAllSubmatch(body, -1) {
		raw := strings.TrimSpace(string(m[1]))
		if raw == "" || raw == "/" {
			continue
		}
		if p := sameHostPath(base, raw); p != "" {
			paths = append(paths, p)
		}
	}
	for _, line := range strings.Split(string(body), "\n") {
		if i := strings.Index(strings.ToLower(line), "sitemap:"); i >= 0 {
			sitemaps = append(sitemaps, strings.TrimSpace(line[i+len("sitemap:"):]))
		}
	}
	return
}

func extractSitemap(base *url.URL, body []byte) []string {
	var out []string
	for _, m := range reSitemap.FindAllSubmatch(body, -1) {
		if p := sameHostPath(base, string(m[1])); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// dirsOf returns the directory prefixes of a path, e.g. /a/b/c.php -> /a/, /a/b/
func dirsOf(p string) []string {
	p = strings.SplitN(p, "?", 2)[0]
	parts := strings.Split(strings.Trim(p, "/"), "/")
	var dirs []string
	cur := "/"
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "" {
			continue
		}
		cur += parts[i] + "/"
		dirs = append(dirs, cur)
	}
	return dirs
}
