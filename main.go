// ghostmap — wordless web attack-surface recon.
// For systems you own or are explicitly authorized to test.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

const version = "0.1.0"

func main() {
	var (
		concurrency = flag.Int("c", 20, "concurrent requests")
		timeout     = flag.Duration("timeout", 10*time.Second, "per-request timeout")
		depth       = flag.Int("depth", 2, "recursion rounds for crawled pages")
		rate        = flag.Int("rate", 0, "max requests/sec (0 = unlimited)")
		maxReq      = flag.Int("max", 2000, "hard cap on total requests")
		ua          = flag.String("ua", "ghostmap/"+version+" (+https://github.com/b3n3d1ck/ghostmap)", "User-Agent")
		insecure    = flag.Bool("insecure", false, "skip TLS certificate verification")
		asJSON      = flag.Bool("json", false, "output JSON")
		outFile     = flag.String("o", "", "write JSON report to file")
		noColor     = flag.Bool("no-color", false, "disable colored output")
		showVer     = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("ghostmap " + version)
		return
	}
	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}

	target, err := normalize(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "target tidak valid:", err)
		os.Exit(2)
	}

	quiet := *asJSON || *outFile != ""
	color := !*noColor && !quiet

	if !quiet {
		banner(color)
		fmt.Printf("%s target  %s\n", dim("»", color), target.String())
		fmt.Printf("%s mode    recon non-destruktif (GET saja) · c=%d depth=%d\n\n", dim("»", color), *concurrency, *depth)
	}

	cl := newClient(*timeout, *insecure, *ua)
	sc := newScanner(cl, target, config{
		concurrency: *concurrency,
		depth:       *depth,
		rate:        *rate,
		maxRequests: *maxReq,
	})
	rep := sc.Run()

	if *outFile != "" {
		b, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*outFile, b, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "gagal menulis file:", err)
			os.Exit(1)
		}
		fmt.Println("laporan JSON ditulis ke", *outFile)
		return
	}
	if *asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
		return
	}
	printReport(rep, color)
}

func usage() {
	fmt.Fprintf(os.Stderr, `ghostmap %s — wordless web attack-surface recon

Pakai: ghostmap [opsi] <url>

Menemukan path & endpoint TANPA wordlist: diekstrak dari JavaScript, robots.txt,
sitemap, link halaman, dan .well-known, lalu recursive. Plus fingerprint teknologi,
cek file sensitif terekspos, dan audit header keamanan. Hanya mengirim GET.

  ghostmap https://situsku.com
  ghostmap -c 40 -depth 3 -json -o hasil.json https://situsku.com

Opsi:
`, version)
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, `
PERINGATAN: jalankan hanya pada sistem yang kamu miliki atau yang kamu
diberi izin tertulis untuk menguji. Memindai sistem orang lain tanpa izin
bisa melanggar hukum.`)
}

func normalize(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Host == "" || !strings.Contains(u.Host, ".") && !strings.Contains(u.Host, ":") {
		return nil, fmt.Errorf("host tidak jelas")
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return u, nil
}

// ---- small helpers ----

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func shortCT(ct string) string {
	return strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])
}

func snippet(body []byte) string {
	s := string(body)
	if len(s) > 160 {
		s = s[:160]
	}
	// mask obvious secrets and collapse whitespace
	s = reSecret.ReplaceAllString(s, "$1***")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

var reSecret = mustSecretRE()

func printReport(r Report, color bool) {
	fmt.Printf("\n%s  %s\n", bold("RINGKASAN", color), dim(fmt.Sprintf("%d request · %dms", r.Requests, r.DurationMS), color))

	if len(r.Tech) > 0 {
		sort.Strings(r.Tech)
		fmt.Printf("\n%s\n", bold("TEKNOLOGI", color))
		for _, t := range r.Tech {
			fmt.Printf("  %s %s\n", cyan("›", color), t)
		}
	}

	if len(r.MissingHeaders) > 0 {
		fmt.Printf("\n%s\n", bold("HEADER KEAMANAN HILANG", color))
		fmt.Printf("  %s\n", yellow(strings.Join(r.MissingHeaders, ", "), color))
	}

	if len(r.Exposures) > 0 {
		fmt.Printf("\n%s\n", bold("⚠ FILE TEREKSPOS", color))
		for _, e := range r.Exposures {
			fmt.Printf("  %s %-22s %s\n", red("✱", color), e.Path, e.Risk)
			if e.Evidence != "" {
				fmt.Printf("      %s\n", dim(e.Evidence, color))
			}
		}
	}

	sort.Slice(r.Paths, func(i, j int) bool {
		if r.Paths[i].Status != r.Paths[j].Status {
			return r.Paths[i].Status < r.Paths[j].Status
		}
		return r.Paths[i].Path < r.Paths[j].Path
	})
	fmt.Printf("\n%s (%d)\n", bold("PATH DITEMUKAN", color), len(r.Paths))
	for _, f := range r.Paths {
		code := statusColor(f.Status, color)
		meta := fmt.Sprintf("%dB", f.Length)
		if f.Title != "" {
			meta += " · " + f.Title
		}
		fmt.Printf("  %s  %-40s %s %s\n", code, f.Path, dim("["+f.Source+"]", color), dim(meta, color))
	}
	if len(r.Paths) == 0 {
		fmt.Println("  " + dim("tidak ada path menarik yang ditemukan", color))
	}
	fmt.Println()
}
