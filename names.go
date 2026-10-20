package main

import (
	"net"
	"strings"
)

func filterNames(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range in {
		n = strings.TrimSpace(strings.ToLower(n))
		n = strings.TrimPrefix(n, "*.")
		if n == "" || seen[n] || strings.ContainsAny(n, " *") || badName(n) {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func badName(n string) bool {
	for _, suf := range []string{".ru", ".ir", ".cn", ".su"} {
		if strings.HasSuffix(n, suf) {
			return true
		}
	}
	for _, s := range []string{"apple", "icloud", "microsoft", "cloudflare", "duckdns", "localhost"} {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

func hosts(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	raw4 := ipnet.IP.To4()
	if raw4 == nil {
		return nil, errNotIPv4(cidr)
	}
	ip := append(net.IP(nil), raw4...)
	var out []string
	for ipnet.Contains(ip) {
		s := ip.String()
		if !strings.HasSuffix(s, ".0") && !strings.HasSuffix(s, ".255") {
			out = append(out, s)
		}
		inc(ip)
	}
	return out, nil
}

type errNotIPv4 string

func (e errNotIPv4) Error() string { return "CIDR is not IPv4: " + string(e) }

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
