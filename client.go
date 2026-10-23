package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxBody = 2 << 20 // 2 MB cap per response

// httpClient wraps an http.Client that never follows redirects, so probes see
// the real status code (301/302/403/...).
type httpClient struct {
	c  *http.Client
	ua string
}

func newClient(timeout time.Duration, insecure bool, ua string) *httpClient {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		DisableKeepAlives:   false,
	}
	return &httpClient{
		c: &http.Client{
			Transport: tr,
			Timeout:   timeout,
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ua: ua,
	}
}

type response struct {
	status      int
	headers     http.Header
	body        []byte
	location    string
	contentType string
	length      int
}

func (h *httpClient) get(url string) (*response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", h.ua)
	req.Header.Set("Accept", "*/*")

	resp, err := h.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return &response{
		status:      resp.StatusCode,
		headers:     resp.Header,
		body:        body,
		location:    resp.Header.Get("Location"),
		contentType: resp.Header.Get("Content-Type"),
		length:      len(body),
	}, nil
}

func (r *response) isHTML() bool {
	return strings.Contains(strings.ToLower(r.contentType), "html")
}

func (r *response) title() string {
	m := reTitle.FindSubmatch(r.body)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(string(m[1]))
	t = strings.Join(strings.Fields(t), " ")
	if len(t) > 80 {
		t = t[:80] + "…"
	}
	return t
}
