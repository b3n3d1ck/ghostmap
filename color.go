package main

import (
	"fmt"
	"regexp"
)

const (
	cresetC  = "\033[0m"
	cdimC    = "\033[2m"
	cboldC   = "\033[1m"
	credC    = "\033[31m"
	cgreenC  = "\033[32m"
	cyellowC = "\033[33m"
	cblueC   = "\033[34m"
	ccyanC   = "\033[36m"
)

func wrap(code, s string, on bool) string {
	if !on {
		return s
	}
	return code + s + cresetC
}

func dim(s string, on bool) string    { return wrap(cdimC, s, on) }
func bold(s string, on bool) string   { return wrap(cboldC, s, on) }
func red(s string, on bool) string    { return wrap(credC, s, on) }
func green(s string, on bool) string  { return wrap(cgreenC, s, on) }
func yellow(s string, on bool) string { return wrap(cyellowC, s, on) }
func cyan(s string, on bool) string   { return wrap(ccyanC, s, on) }

func statusColor(code int, on bool) string {
	s := fmt.Sprintf("%d", code)
	switch {
	case code >= 200 && code < 300:
		return green(s, on)
	case code >= 300 && code < 400:
		return cyan(s, on)
	case code == 401 || code == 403:
		return yellow(s, on)
	case code >= 500:
		return red(s, on)
	}
	return wrap(cblueC, s, on)
}

func banner(on bool) {
	art := `
  ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓ ███▄ ▄███▓ ▄▄▄       ██▓███
 ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒
▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒
░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░ ▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒
░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ ▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░
 ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░   ░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░`
	fmt.Println(green(art, on))
	fmt.Println(dim("  wordless web attack-surface recon · v"+version, on))
	fmt.Println(dim("  gunakan hanya pada target yang kamu miliki / diizinkan", on))
}

func mustSecretRE() *regexp.Regexp {
	return regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api[_-]?key|app[_-]?key|db[_-]?password)\s*[=:]\s*)\S+`)
}
