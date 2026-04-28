package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

// ── Linear search — O(n) substring across all finding fields ─────────────────

func searchFindings(findings []Finding, query string) []Finding {
	q := strings.ToLower(query)
	var results []Finding
	for _, f := range findings {
		if findingMatches(f, q) {
			results = append(results, f)
		}
	}
	return results
}

func findingMatches(f Finding, q string) bool {
	fields := []string{
		f.ID, f.Title, string(f.Severity),
		f.Host, f.URL, f.Evidence, f.Check, f.Phase,
		fmt.Sprintf("%d", f.Port),
	}
	fields = append(fields, f.Tags...)
	fields = append(fields, f.Signals...)
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), q) {
			return true
		}
	}
	return false
}

// ── Binary search — O(log n) exact port lookup ────────────────────────────────
// sortedPorts is initialized in ports.go init().

func findPort(port int) *portDef {
	lo, hi := 0, len(sortedPorts)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		switch {
		case sortedPorts[mid].port == port:
			p := sortedPorts[mid]
			return &p
		case sortedPorts[mid].port < port:
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}
	return nil
}

// ── search subcommand ─────────────────────────────────────────────────────────

func runSearch(args []string) {
	fs := flag.NewFlagSet("search", flag.ExitOnError)
	inFile := fs.String("in", "", "Input JSON report file")
	query  := fs.String("q", "", "Substring query across all fields")
	sev    := fs.String("sev", "", "Filter by severity (CRITICAL|HIGH|MEDIUM|LOW|INFO)")
	port   := fs.Int("port", 0, "Look up a port number in the port table")
	fs.Parse(args)

	if *port != 0 {
		pd := findPort(*port)
		if pd == nil {
			fmt.Fprintf(os.Stderr, "port %d not in menlohunt port list\n", *port)
			os.Exit(1)
		}
		fmt.Printf("port     : %d/tcp\n", pd.port)
		fmt.Printf("service  : %s\n", pd.service)
		fmt.Printf("severity : %s\n", pd.sev)
		fmt.Printf("tags     : %s\n", strings.Join(pd.tags, ", "))
		return
	}

	if *inFile == "" {
		fs.Usage()
		os.Exit(1)
	}

	data, err := os.ReadFile(*inFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read error: %v\n", err)
		os.Exit(1)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
		os.Exit(1)
	}

	results := report.Findings
	if *query != "" {
		results = searchFindings(results, *query)
	}
	if *sev != "" {
		want := strings.ToUpper(*sev)
		var filtered []Finding
		for _, f := range results {
			if string(f.Severity) == want {
				filtered = append(filtered, f)
			}
		}
		results = filtered
	}

	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "no matches")
		os.Exit(0)
	}
	out, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(out))
	fmt.Fprintf(os.Stderr, "%d/%d findings matched\n", len(results), len(report.Findings))
}

// ── report subcommand ─────────────────────────────────────────────────────────

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	inFile := fs.String("in", "", "Input JSON report file")
	fs.Parse(args)

	if *inFile == "" {
		fs.Usage()
		os.Exit(1)
	}

	data, err := os.ReadFile(*inFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read error: %v\n", err)
		os.Exit(1)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
		os.Exit(1)
	}

	bold, reset, dim := "\033[1m", "\033[0m", "\033[2m"
	fmt.Printf("\n%s━━━ menlohunt report ━━━%s\n", bold, reset)
	fmt.Printf("Target   : %s\n", report.Target)
	fmt.Printf("DNS      : %s\n", strings.Join(report.ReverseDNS, ", "))
	fmt.Printf("Started  : %s\n", report.StartedAt)
	fmt.Printf("Duration : %s\n", report.Duration)
	fmt.Printf("Findings : %d  %s[C:%d H:%d M:%d L:%d I:%d]%s\n\n",
		len(report.Findings), bold,
		report.Summary["CRITICAL"], report.Summary["HIGH"],
		report.Summary["MEDIUM"], report.Summary["LOW"], report.Summary["INFO"],
		reset)

	for _, sev := range []Severity{Critical, High, Medium, Low, Info} {
		var group []Finding
		for _, f := range report.Findings {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		fmt.Printf("%s%s[%s]%s\n", bold, sev.Color(), sev, reset)
		for _, f := range group {
			fmt.Printf("  %s%s%s  %s\n", sev.Color(), f.ID, reset, f.Title)
			fmt.Printf("  %s%s:%d  %s%s\n", dim, f.Host, f.Port, f.URL, reset)
			fmt.Printf("  %s%s%s\n\n", dim, trunc(f.Evidence, 120), reset)
		}
	}

	if len(report.AttackChains) > 0 {
		fmt.Printf("%s━━━ attack chains ━━━%s\n", bold, reset)
		for i, chain := range report.AttackChains {
			fmt.Printf("%s  [chain %d] score=%d tags=[%s]%s\n",
				Critical.Color(), i+1, chain.TotalScore,
				strings.Join(chain.SharedTags, ", "), reset)
			for j, title := range chain.Titles {
				fmt.Printf("    %s → %s\n", chain.FindingIDs[j], title)
			}
			fmt.Println()
		}
	}
}
