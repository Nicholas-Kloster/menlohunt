package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// iterCIDR calls fn for each host address in the CIDR (skips .0 and .255).
// net.IP is []byte — increment in-place; no big.Int needed.
func iterCIDR(cidr string, fn func(string)) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return fmt.Errorf("IPv6 not supported")
	}
	cur := make(net.IP, 4)
	copy(cur, ip)
	for ipnet.Contains(cur) {
		if cur[3] != 0 && cur[3] != 255 {
			fn(cur.String())
		}
		for j := 3; j >= 0; j-- {
			cur[j]++
			if cur[j] != 0 {
				break
			}
		}
	}
	return nil
}

func runSweep(args []string) {
	fs := flag.NewFlagSet("sweep", flag.ExitOnError)
	prefixFile  := fs.String("prefixes", "gcp_targets.txt", "one CIDR per line")
	workers     := fs.Int("workers", 4000, "concurrent goroutines")
	outFile     := fs.String("out", "findings.ndjson", "NDJSON output")
	skipSmaller := fs.Int("min-prefix", 20, "skip CIDRs with prefix length < this (too large to sweep)")
	dashAddr    := fs.String("dash", "127.0.0.1:7331", "live dashboard address (empty = disabled)")
	noICMP      := fs.Bool("no-icmp", false, "disable ICMP host pre-filter")
	timeout     := fs.Int("timeout", 2, "per-probe timeout in seconds")
	fs.Parse(args)

	to := time.Duration(*timeout) * time.Second

	if !*noICMP {
		initICMP()
	}

	ndFile, err := os.Create(*outFile)
	if err != nil {
		log.Fatal(err)
	}
	defer ndFile.Close()
	enc := json.NewEncoder(ndFile)

	sweepEmit = func(f Finding) {
		enc.Encode(f)
	}

	if *dashAddr != "" {
		h := newHub()
		globalHub = h
		startDashboard(h, *dashAddr)
	}

	logf := func(msg string, a ...any) {
		fmt.Fprintf(os.Stderr, "[sweep] "+msg+"\n", a...)
	}

	// Load CIDRs
	pf, err := os.Open(*prefixFile)
	if err != nil {
		log.Fatal(err)
	}
	var cidrs []string
	sc := bufio.NewScanner(pf)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		if ones < *skipSmaller {
			logf("skip %s (/%d < /%d)", line, ones, *skipSmaller)
			continue
		}
		cidrs = append(cidrs, line)
	}
	pf.Close()
	logf("%d CIDRs loaded (min-prefix=/%d, workers=%d)", len(cidrs), *skipSmaller, *workers)

	// Stream IPs from CIDRs into the channel
	ipCh := make(chan string, *workers*8)
	var totalIPs atomic.Int64
	go func() {
		for _, cidr := range cidrs {
			iterCIDR(cidr, func(ip string) {
				totalIPs.Add(1)
				ipCh <- ip
			})
		}
		close(ipCh)
	}()

	var (
		probed atomic.Int64
		hits   atomic.Int64
		wg     sync.WaitGroup
	)
	sem := make(chan struct{}, *workers)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Progress ticker
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				tot := totalIPs.Load()
				done := probed.Load()
				pct := 0.0
				if tot > 0 {
					pct = float64(done) / float64(tot) * 100
				}
				logf("probed=%d/%d (%.1f%%) hits=%d", done, tot, pct, hits.Load())
			}
		}
	}()

	for ip := range ipCh {
		sem <- struct{}{}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			probed.Add(1)

			// ICMP pre-filter: skip dark IPs before wasting HTTP roundtrips
			if !icmpAlive(ip) {
				return
			}

			// Phase 1: redge ports via HTTP GET (L7 firewall bypass)
			httpHit := false
			for _, port := range []int{8082, 8086} {
				if httpOpen(ip, port, to) {
					hits.Add(1)
					addFinding(Finding{
						Title:    fmt.Sprintf("Open port %d/tcp — redge service", port),
						Severity: Medium,
						Phase:    "phase1",
						Check:    "port_open",
						Host:     ip,
						Port:     port,
						Proto:    "tcp",
						Evidence: fmt.Sprintf("HTTP GET to %s:%d succeeded", ip, port),
						Tags:     []string{"redge", "menlorecast", "port-scan"},
					})

					// Phase 2: HTTP fingerprint for redge signatures
					client := newClient(to)
					checkHTTP(ip, port, "http", to, 0)
					_ = client
					httpHit = true
				}
			}

			// WireGuard UDP probe — run on ICMP-alive hosts
			for _, port := range wgPorts {
				if wgProbe(ip, port) {
					hits.Add(1)
					addFinding(Finding{
						Title:    fmt.Sprintf("WireGuard endpoint candidate — UDP %d open/filtered", port),
						Severity: Medium,
						Phase:    "phase1",
						Check:    "wg_probe",
						Host:     ip,
						Port:     port,
						Proto:    "udp",
						Status:   "open_or_filtered",
						Evidence: "Noise HandshakeInitiation timed out (WireGuard drops malformed MAC1)",
						Tags:     []string{"wireguard", "redge", "menlorecast", "udp"},
					})
				}
			}

			// BGP/179
			if tcpOpen(ip, 179, to) {
				hits.Add(1)
				addFinding(Finding{
					Title:    "BGP port 179/tcp open",
					Severity: Low,
					Phase:    "phase1",
					Check:    "bgp_open",
					Host:     ip,
					Port:     179,
					Proto:    "tcp",
					Evidence: fmt.Sprintf("TCP connect to %s:179 succeeded", ip),
					Tags:     []string{"bgp", "routing", "redge"},
				})
			}

			// Phase 3: GCP vuln checks on confirmed redge nodes
			if httpHit {
				checkMetadataAPI(ip, to)
				names := extractNames(ip, reverseDNS(ip))
				checkGCS(ip, names, to)
			}
		}(ip)
	}
	wg.Wait()
	cancel()

	// Final report
	allFindings := snapshot()
	chains := detectChains(allFindings)
	summary := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range allFindings {
		summary[string(f.Severity)]++
	}
	report := Report{
		Target:       *prefixFile,
		StartedAt:    "",
		Findings:     allFindings,
		Summary:      summary,
		AttackChains: chains,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		logf("report marshal error: %v", err)
	} else {
		reportFile := strings.TrimSuffix(*outFile, ".ndjson") + "_report.json"
		os.WriteFile(reportFile, data, 0644)
		logf("report → %s", reportFile)
	}

	logf("done — probed=%d hits=%d findings=%d chains=%d [C:%d H:%d M:%d L:%d I:%d]",
		probed.Load(), hits.Load(), len(allFindings), len(chains),
		summary["CRITICAL"], summary["HIGH"], summary["MEDIUM"],
		summary["LOW"], summary["INFO"])
}
