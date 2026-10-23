package main

import (
	"net/url"
	"strings"
	"sync"
	"time"
)

// Finding is a discovered path and what the server returned for it.
type Finding struct {
	Path        string `json:"path"`
	Status      int    `json:"status"`
	Length      int    `json:"length"`
	ContentType string `json:"content_type,omitempty"`
	Title       string `json:"title,omitempty"`
	Source      string `json:"source"` // html, js, robots, sitemap, recursive
}

// Exposure is a sensitive file that was found readable.
type Exposure struct {
	Path     string `json:"path"`
	Status   int    `json:"status"`
	Risk     string `json:"risk"`
	Evidence string `json:"evidence,omitempty"`
}

type Report struct {
	Target         string     `json:"target"`
	FinalURL       string     `json:"final_url"`
	Tech           []string   `json:"tech"`
	MissingHeaders []string   `json:"missing_security_headers"`
	Paths          []Finding  `json:"paths"`
	Exposures      []Exposure `json:"exposures"`
	Requests       int        `json:"requests"`
	DurationMS     int64      `json:"duration_ms"`
}

type config struct {
	concurrency int
	depth       int
	rate        int // requests/sec, 0 = unlimited
	maxRequests int
}

type scanner struct {
	cl   *httpClient
	base *url.URL
	cfg  config

	mu       sync.Mutex
	seen     map[string]bool
	findings []Finding
	reqCount int

	sem     chan struct{}
	limiter <-chan time.Time
}

func newScanner(cl *httpClient, base *url.URL, cfg config) *scanner {
	s := &scanner{
		cl:   cl,
		base: base,
		cfg:  cfg,
		seen: map[string]bool{},
		sem:  make(chan struct{}, cfg.concurrency),
	}
	if cfg.rate > 0 {
		s.limiter = time.Tick(time.Second / time.Duration(cfg.rate))
	}
	return s
}

func (s *scanner) url(path string) string {
	return s.base.Scheme + "://" + s.base.Host + path
}

func (s *scanner) budget() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reqCount >= s.cfg.maxRequests {
		return false
	}
	s.reqCount++
	return true
}

// fetch respects the rate limiter and request budget.
func (s *scanner) fetch(path string) (*response, bool) {
	if !s.budget() {
		return nil, false
	}
	if s.limiter != nil {
		<-s.limiter
	}
	r, err := s.cl.get(s.url(path))
	if err != nil {
		return nil, false
	}
	return r, true
}

// Run executes the full recon pipeline and returns a report.
func (s *scanner) Run() Report {
	start := time.Now()
	rep := Report{Target: s.base.String()}

	soft404 := s.softNotFound()

	root, ok := s.fetch("/")
	if ok {
		rep.FinalURL = s.url("/")
		rep.Tech = fingerprint(root)
		rep.MissingHeaders = missingSecurityHeaders(root)
	}

	// --- seed discovery (no wordlist) ---
	seed := map[string]string{} // path -> source
	addSeed := func(ps []string, src string) {
		for _, p := range ps {
			if _, ok := seed[p]; !ok {
				seed[p] = src
			}
			for _, d := range dirsOf(p) {
				if _, ok := seed[d]; !ok {
					seed[d] = src
				}
			}
		}
	}

	if root != nil {
		addSeed(extractFromHTML(s.base, root.body), "html")
		// JS files referenced by the page -> extract endpoints from them
		for _, js := range s.jsURLs(root.body) {
			if r, ok := s.fetch(js); ok {
				addSeed(extractFromJS(s.base, r.body), "js")
			}
		}
	}
	if r, ok := s.fetch("/robots.txt"); ok && r.status == 200 {
		paths, sms := extractRobots(s.base, r.body)
		addSeed(paths, "robots")
		for _, sm := range sms {
			if p := sameHostPath(s.base, sm); p != "" {
				if rr, ok := s.fetch(p); ok {
					addSeed(extractSitemap(s.base, rr.body), "sitemap")
				}
			}
		}
	}
	if r, ok := s.fetch("/sitemap.xml"); ok && r.status == 200 {
		addSeed(extractSitemap(s.base, r.body), "sitemap")
	}

	// --- probe seeds, then recurse into HTML pages ---
	frontier := make([]string, 0, len(seed))
	srcOf := map[string]string{}
	for p, src := range seed {
		frontier = append(frontier, p)
		srcOf[p] = src
	}

	for round := 0; round <= s.cfg.depth; round++ {
		if len(frontier) == 0 {
			break
		}
		found := s.probeBatch(frontier, srcOf, soft404)
		next := map[string]bool{}
		for _, f := range found {
			if f.Status == 200 && strings.Contains(strings.ToLower(f.ContentType), "html") {
				if r, ok := s.fetch(f.Path); ok {
					for _, np := range extractFromHTML(s.base, r.body) {
						if !s.isSeen(np) {
							next[np] = true
							srcOf[np] = "recursive"
						}
					}
				}
			}
		}
		frontier = frontier[:0]
		for p := range next {
			frontier = append(frontier, p)
		}
	}

	// --- sensitive files ---
	rep.Exposures = s.probeSensitive(soft404)

	rep.Paths = s.findings
	rep.Requests = s.reqCount
	rep.DurationMS = time.Since(start).Milliseconds()
	return rep
}

type baseline struct {
	is200  bool
	length int
}

func (s *scanner) softNotFound() baseline {
	r, ok := s.fetch("/ghostmap-" + randHex(10) + "-notfound")
	if !ok {
		return baseline{}
	}
	return baseline{is200: r.status == 200, length: r.length}
}

func (s *scanner) isSeen(p string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[p]
}

func (s *scanner) markSeen(p string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[p] {
		return false
	}
	s.seen[p] = true
	return true
}

// probeBatch probes paths concurrently, records interesting findings, returns them.
func (s *scanner) probeBatch(paths []string, srcOf map[string]string, b baseline) []Finding {
	var wg sync.WaitGroup
	var local []Finding
	var lmu sync.Mutex

	for _, p := range paths {
		if !s.markSeen(p) {
			continue
		}
		wg.Add(1)
		s.sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-s.sem }()
			r, ok := s.fetch(path)
			if !ok {
				return
			}
			if !interesting(r, b) {
				return
			}
			f := Finding{
				Path:        path,
				Status:      r.status,
				Length:      r.length,
				ContentType: shortCT(r.contentType),
				Source:      srcOf[path],
			}
			if r.isHTML() {
				f.Title = r.title()
			}
			lmu.Lock()
			local = append(local, f)
			lmu.Unlock()
			s.mu.Lock()
			s.findings = append(s.findings, f)
			s.mu.Unlock()
		}(p)
	}
	wg.Wait()
	return local
}

func (s *scanner) probeSensitive(b baseline) []Exposure {
	var wg sync.WaitGroup
	var out []Exposure
	var mu sync.Mutex
	for _, sf := range sensitiveFiles {
		wg.Add(1)
		s.sem <- struct{}{}
		go func(sf sensitiveFile) {
			defer wg.Done()
			defer func() { <-s.sem }()
			r, ok := s.fetch(sf.path)
			if !ok || r.status != 200 {
				return
			}
			if b.is200 && !sf.sig.Match(r.body) {
				return
			}
			if !sf.sig.Match(r.body) {
				return
			}
			mu.Lock()
			out = append(out, Exposure{Path: sf.path, Status: r.status, Risk: sf.risk, Evidence: snippet(r.body)})
			mu.Unlock()
		}(sf)
	}
	wg.Wait()
	return out
}

func (s *scanner) jsURLs(body []byte) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range reAttr.FindAllSubmatch(body, -1) {
		ref := string(m[1])
		if !strings.Contains(strings.ToLower(ref), ".js") {
			continue
		}
		if p := sameHostPath(s.base, ref); p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
			if len(out) >= 25 {
				break
			}
		}
	}
	return out
}

func interesting(r *response, b baseline) bool {
	switch r.status {
	case 404:
		return false
	case 200:
		if b.is200 && abs(r.length-b.length) < 24 {
			return false // looks like the soft-404 page
		}
		return true
	case 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 503:
		return true
	}
	return false
}
