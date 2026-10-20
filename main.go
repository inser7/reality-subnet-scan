package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, ",") }

func (s *stringsFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type raw struct {
	ip, issuer, names string
}

func main() {
	var cidrs stringsFlag
	var skips stringsFlag
	flag.Var(&cidrs, "addr", "CIDR to scan, repeat for several (required)")
	flag.Var(&skips, "skip", "IP to skip, repeat for several")
	iface := flag.String("iface", "", "outgoing interface (en0 when a VPN tunnel is the default route)")
	port := flag.Int("port", 443, "TCP port")
	threads := flag.Int("threads", 32, "concurrent handshakes")
	dialTimeout := flag.Duration("timeout", 2*time.Second, "TCP dial timeout")
	dnsServer := flag.String("dns", "8.8.8.8:53", "DNS server for the A-record check")
	flag.Parse()

	if len(cidrs) == 0 {
		fmt.Fprintln(os.Stderr, "pass at least one -addr CIDR")
		flag.Usage()
		os.Exit(2)
	}
	if *threads < 1 {
		fmt.Fprintln(os.Stderr, "-threads must be >= 1")
		os.Exit(2)
	}

	control, err := bindControl(*iface)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	skip := map[string]bool{}
	for _, ip := range skips {
		if net.ParseIP(ip) == nil {
			fmt.Fprintf(os.Stderr, "skip is not an IP: %s\n", ip)
			os.Exit(2)
		}
		skip[ip] = true
	}

	var ips []string
	for _, c := range cidrs {
		list, err := hosts(c)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		ips = append(ips, list...)
	}

	fmt.Fprintf(os.Stderr, "scanning %d addresses\n", len(ips))
	jobs := make(chan string)
	var mu sync.Mutex
	var found []raw
	var done, open, hits atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: *dialTimeout, Control: control}
			for ip := range jobs {
				n := done.Add(1)
				if n%100 == 0 {
					fmt.Fprintf(os.Stderr, "progress %d/%d open=%d hits=%d\n", n, len(ips), open.Load(), hits.Load())
				}
				conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, fmt.Sprint(*port)))
				if err != nil {
					continue
				}
				open.Add(1)
				_ = conn.SetDeadline(time.Now().Add(*dialTimeout + time.Second))
				tc := tls.Client(conn, &tls.Config{
					InsecureSkipVerify: true,
					NextProtos:         []string{"h2", "http/1.1"},
					MinVersion:         tls.VersionTLS13,
					CurvePreferences:   []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
				})
				err = tc.Handshake()
				st := tc.ConnectionState()
				_ = tc.Close()
				if err != nil || st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "h2" || len(st.PeerCertificates) == 0 {
					continue
				}
				leaf := st.PeerCertificates[0]
				names := append([]string{}, leaf.DNSNames...)
				if leaf.Subject.CommonName != "" {
					names = append(names, leaf.Subject.CommonName)
				}
				names = filterNames(names)
				if len(names) == 0 {
					continue
				}
				hits.Add(1)
				row := raw{ip: ip, issuer: strings.Join(leaf.Issuer.Organization, " "), names: strings.Join(names, " ")}
				mu.Lock()
				found = append(found, row)
				fmt.Printf("TLS\t%s\t%s\t%s\n", row.ip, row.issuer, row.names)
				mu.Unlock()
			}
		}()
	}
	for _, ip := range ips {
		if !skip[ip] {
			jobs <- ip
		}
	}
	close(jobs)
	wg.Wait()
	fmt.Fprintf(os.Stderr, "scan done open=%d tls=%d\n", open.Load(), hits.Load())

	for _, row := range found {
		for _, name := range strings.Fields(row.names) {
			if resolvesTo(name, row.ip, *dnsServer, control) {
				fmt.Printf("MATCH\t%s\t%s\t%s\n", row.ip, name, row.issuer)
				break
			}
		}
	}
}

func resolvesTo(name, ip, dnsServer string, control func(string, string, syscallRaw) error) bool {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second, Control: control}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := r.LookupHost(ctx, name)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if a == ip {
			return true
		}
	}
	return false
}
