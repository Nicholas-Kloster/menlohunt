// menlohunt — GCP / redge external vulnerability scanner
//
// USAGE
//   menlohunt scan   -ip <IP> [-out <file.json>] [-timeout <s>] [-retries <n>] [-dash <addr>]
//   menlohunt sweep  -prefixes <file> [-workers N] [-out <file>] [-timeout <s>] [-dash <addr>]
//   menlohunt search -in <file.json> [-q <query>] [-sev CRITICAL|HIGH|MEDIUM|LOW|INFO]
//   menlohunt search -port <number>
//   menlohunt report -in <file.json>

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const version = "0.3.0"

const colorCyan = "\033[36m"
const colorGray = "\033[90m"

func printBanner() {
	banner := `
    __  ___            __      __                      __
   /  |/  /___  ____  / /___  / /_  __  ______  ______/ /_
  / /|_/ / __ \/ __ \/ / __ \/ __ \/ / / / __ \/ __  / __/
 / /  / /  __/ / / / / /_/ / / / / /_/ / / / / /_/ / /_
/_/  /_/\___/_/ /_/_/\____/_/ /_/\__,_/_/ /_/\__,_/\__/
`
	fmt.Fprintf(os.Stderr, "%s%s%s", colorCyan, banner, colorReset)
	fmt.Fprintf(os.Stderr, "%s  v%s — GCP External Attack Surface Management (EASM)%s\n", colorGray, version, colorReset)
	fmt.Fprintf(os.Stderr, "%s  Zero-knowledge perimeter auditing and attack chain discovery.%s\n\n", colorGray, colorReset)
}

const usage = `menlohunt v` + version + ` — GCP / redge external vulnerability scanner

SUBCOMMANDS
  scan    deep per-IP scan (port sweep + HTTP + TLS + GCP + WireGuard)
  sweep   CIDR sweep with ICMP pre-filter and redge-specific checks
  search  query a saved report (substring or severity filter)
  report  render a saved report to the terminal
  search -port <N>  look up a port in the port table

EXAMPLES
  menlohunt scan -ip 185.116.97.167 -out /tmp/scan.json
  menlohunt report -in /tmp/scan.json
  menlohunt search -in /tmp/scan.json -sev CRITICAL
  menlohunt search -in /tmp/scan.json -q redis
  menlohunt search -port 8082
  menlohunt sweep -prefixes gcp_targets.txt -workers 4000 -dash 127.0.0.1:7331
`

func main() {
	if len(os.Args) > 1 && os.Args[1] != "version" && os.Args[1] != "-version" && os.Args[1] != "--version" {
		printBanner()
	}
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}
	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "sweep":
		runSweep(os.Args[2:])
	case "search":
		runSearch(os.Args[2:])
	case "report":
		runReport(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Printf("menlohunt %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %q\n\n", os.Args[1])
		fmt.Print(usage)
		os.Exit(1)
	}
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	ip       := fs.String("ip",      "",  "Target IP address (required)")
	out      := fs.String("out",     "",  "Output JSON file (stdout if omitted)")
	timeout  := fs.Int(   "timeout", 4,   "Per-probe timeout in seconds")
	retries  := fs.Int(   "retries", 1,   "HTTP retry count (fibonacci backoff)")
	dashAddr := fs.String("dash",    "",  "Live dashboard address (e.g. 127.0.0.1:7331)")
	noICMP   := fs.Bool(  "no-icmp", false, "Skip ICMP host reachability check")
	fs.Parse(args)

	if *ip == "" {
		fmt.Fprintln(os.Stderr, "scan: -ip is required")
		fs.Usage()
		os.Exit(1)
	}

	if !*noICMP {
		initICMP()
	}
	if *dashAddr != "" {
		h := newHub()
		globalHub = h
		startDashboard(h, *dashAddr)
	}

	to := time.Duration(*timeout) * time.Second
	start := time.Now()
	logf := func(msg string, a ...any) {
		fmt.Fprintf(os.Stderr, "[menlohunt] "+msg+"\n", a...)
	}
	logf("v%s  target=%s  timeout=%s  retries=%d", version, *ip, to, *retries)

	// ICMP reachability check (informational only — scan continues regardless)
	if icmpEnabled.Load() {
		if icmpAlive(*ip) {
			logf("ICMP: host is alive")
		} else {
			logf("ICMP: no response — host may be down or ICMP filtered")
		}
	}

	hosts := reverseDNS(*ip)
	names := extractNames(*ip, hosts)
	logf("reverse DNS: %v", hosts)
	logf("name candidates: %v", names)

	// Phase 1: port scan
	logf("phase 1 — port scan (%d ports)…", len(portList))
	openPorts := scanPorts(*ip, to)
	logf("open ports: [%s]", openPortList(openPorts))

	// Phase 2: raw probes + HTTP fingerprinting (parallel)
	logf("phase 2 — protocol probes + HTTP fingerprinting…")
	var wg2 sync.WaitGroup
	wg2.Add(2)
	go func() { defer wg2.Done(); runProbes(*ip, openPorts, to) }()
	go func() { defer wg2.Done(); runHTTPChecks(*ip, openPorts, to, *retries) }()
	wg2.Wait()

	// WireGuard UDP probe
	logf("phase 2 — WireGuard UDP probe…")
	for _, port := range wgPorts {
		if wgProbe(*ip, port) {
			addFinding(Finding{
				Title:    fmt.Sprintf("WireGuard endpoint candidate — UDP %d open/filtered", port),
				Severity: Medium,
				Phase:    "phase2",
				Check:    "wg_probe",
				Host:     *ip,
				Port:     port,
				Proto:    "udp",
				Status:   "open_or_filtered",
				Evidence: "Noise HandshakeInitiation timed out (WireGuard drops malformed MAC1)",
				Tags:     []string{"wireguard", "redge", "menlorecast", "udp"},
			})
		}
	}

	// Phase 3: TLS
	logf("phase 3 — TLS certificate analysis…")
	runTLSChecks(*ip, openPorts, to)

	// Phase 4: GCP surface (parallel)
	logf("phase 4 — GCP surface (GCS, Firebase, metadata, Cloud Run)…")
	var wg4 sync.WaitGroup
	wg4.Add(4)
	go func() { defer wg4.Done(); checkGCS(*ip, names, to) }()
	go func() { defer wg4.Done(); checkFirebase(names, to) }()
	go func() { defer wg4.Done(); checkMetadataAPI(*ip, to) }()
	go func() { defer wg4.Done(); checkCloudRunFunctions(names, to) }()
	wg4.Wait()

	// Phase 5: attack chain detection
	logf("phase 5 — attack chain detection (threshold=%d)…", chainThreshold)
	allFindings := snapshot()
	chains := detectChains(allFindings)
	logf("chains: %d", len(chains))

	summary := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range allFindings {
		summary[string(f.Severity)]++
	}

	report := Report{
		Target:       *ip,
		ReverseDNS:   hosts,
		StartedAt:    start.UTC().Format(time.RFC3339),
		Duration:     time.Since(start).Round(time.Millisecond).String(),
		Findings:     allFindings,
		Summary:      summary,
		AttackChains: chains,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal error: %v\n", err)
		os.Exit(1)
	}

	if *out != "" {
		if err := os.WriteFile(*out, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "write error: %v\n", err)
			os.Exit(1)
		}
		logf("wrote %s", *out)
	} else {
		fmt.Println(string(data))
	}

	logf("done — %d findings, %d chains in %s  [C:%d H:%d M:%d L:%d I:%d]",
		len(allFindings), len(chains),
		time.Since(start).Round(time.Millisecond),
		summary["CRITICAL"], summary["HIGH"], summary["MEDIUM"],
		summary["LOW"], summary["INFO"])
}

func openPortList(m map[int]bool) string {
	var ports []string
	for p := range m {
		ports = append(ports, fmt.Sprintf("%d", p))
	}
	return strings.Join(ports, ", ")
}
