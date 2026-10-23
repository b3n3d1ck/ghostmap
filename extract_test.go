package main

import (
	"net/url"
	"testing"
)

func mustURL(t *testing.T, s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestSameHostPath(t *testing.T) {
	base := mustURL(t, "https://site.com/")
	cases := map[string]string{
		"/admin/":                "/admin/",
		"css/app.css":            "/css/app.css",
		"https://site.com/x?a=1": "/x?a=1",
		"https://evil.com/x":     "",
		"mailto:a@b.com":         "",
		"javascript:void(0)":     "",
		"//cdn.other.com/lib.js": "",
	}
	for in, want := range cases {
		if got := sameHostPath(base, in); got != want {
			t.Errorf("sameHostPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractFromJS(t *testing.T) {
	base := mustURL(t, "https://site.com/")
	js := []byte(`const a="/api/v1/users";fetch('/api/v1/admin/config');var u="/internal/x.php?id=1";let z="/static/app.js";`)
	got := extractFromJS(base, js)
	for _, want := range []string{"/api/v1/users", "/api/v1/admin/config", "/internal/x.php?id=1"} {
		if !contains(got, want) {
			t.Errorf("extractFromJS missing %q, got %v", want, got)
		}
	}
}

func TestExtractFromHTML(t *testing.T) {
	base := mustURL(t, "https://site.com/")
	html := []byte(`<a href="/login">x</a><script src="/app.js"></script><a href="https://evil.com/x">y</a>`)
	got := extractFromHTML(base, html)
	if !contains(got, "/login") || !contains(got, "/app.js") {
		t.Errorf("extractFromHTML = %v", got)
	}
	if contains(got, "https://evil.com/x") {
		t.Errorf("extractFromHTML leaked cross-origin url: %v", got)
	}
}

func TestExtractRobots(t *testing.T) {
	base := mustURL(t, "https://site.com/")
	body := []byte("User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nSitemap: https://site.com/sitemap.xml\n")
	paths, sitemaps := extractRobots(base, body)
	if !contains(paths, "/admin/") || !contains(paths, "/backup/") {
		t.Errorf("robots paths = %v", paths)
	}
	if len(sitemaps) != 1 {
		t.Errorf("robots sitemaps = %v", sitemaps)
	}
}

func TestDirsOf(t *testing.T) {
	got := dirsOf("/a/b/c.php?id=1")
	if len(got) != 2 || got[0] != "/a/" || got[1] != "/a/b/" {
		t.Errorf("dirsOf = %v", got)
	}
}

func TestNormalize(t *testing.T) {
	u, err := normalize("example.com")
	if err != nil || u.String() != "https://example.com" {
		t.Errorf("normalize add https failed: %v %v", u, err)
	}
	if _, err := normalize("not a host"); err == nil {
		t.Error("normalize should reject junk")
	}
}

func TestSnippetMasksSecrets(t *testing.T) {
	out := snippet([]byte("DB_PASSWORD=hunter2 and APP_KEY=base64:abc"))
	if contains([]string{out}, "hunter2") {
	}
	if got := out; got == "" || (len(got) > 0 && (containsStr(got, "hunter2") || containsStr(got, "base64:abc"))) {
		t.Errorf("snippet leaked secret: %q", got)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
