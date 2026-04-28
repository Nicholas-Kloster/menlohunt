package main

import (
	"fmt"
	"sync"
	"time"
)

// ── Severity ──────────────────────────────────────────────────────────────────

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

func (s Severity) Score() int {
	switch s {
	case Critical:
		return 10
	case High:
		return 7
	case Medium:
		return 4
	case Low:
		return 1
	default:
		return 0
	}
}

func (s Severity) Color() string {
	switch s {
	case Critical:
		return "\033[1;31m"
	case High:
		return "\033[31m"
	case Medium:
		return "\033[33m"
	case Low:
		return "\033[36m"
	default:
		return "\033[37m"
	}
}

const colorReset = "\033[0m"

// ── Finding ───────────────────────────────────────────────────────────────────
// Superset of both tools: structured report fields (ID, Title, Severity, Tags,
// Evidence) plus raw scanner detail (Phase, Check, Proto, Status, Signals, Body).

type Finding struct {
	ID       string            `json:"id"`
	Title    string            `json:"title"`
	Severity Severity          `json:"severity"`
	Phase    string            `json:"phase,omitempty"`
	Check    string            `json:"check,omitempty"`
	Host     string            `json:"host"`
	Port     int               `json:"port,omitempty"`
	Proto    string            `json:"proto,omitempty"`
	URL      string            `json:"url,omitempty"`
	Status   string            `json:"status,omitempty"`
	Evidence string            `json:"evidence"`
	Signals  []string          `json:"signals,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
	Tags     []string          `json:"tags"`
	TS       string            `json:"timestamp"`
}

// ── Report types ──────────────────────────────────────────────────────────────

type AttackChain struct {
	TotalScore int      `json:"total_score"`
	FindingIDs []string `json:"finding_ids"`
	Titles     []string `json:"titles"`
	SharedTags []string `json:"shared_tags"`
}

type Report struct {
	Target       string         `json:"target"`
	ReverseDNS   []string       `json:"reverse_dns"`
	StartedAt    string         `json:"started_at"`
	Duration     string         `json:"duration"`
	Findings     []Finding      `json:"findings"`
	Summary      map[string]int `json:"summary"`
	AttackChains []AttackChain  `json:"attack_chains,omitempty"`
}

type portDef struct {
	port    int
	service string
	sev     Severity
	tags    []string
}

// ── Global state ──────────────────────────────────────────────────────────────

var (
	mu        sync.Mutex
	findings  []Finding
	counter   int
	globalHub *hub       // set by main when dashboard is enabled
	sweepEmit func(Finding) // set by runSweep for NDJSON streaming
)

func addFinding(f Finding) {
	mu.Lock()
	counter++
	f.ID = fmt.Sprintf("MH-%04d", counter)
	if f.TS == "" {
		f.TS = time.Now().UTC().Format(time.RFC3339)
	}
	findings = append(findings, f)
	h := globalHub
	e := sweepEmit
	mu.Unlock()

	if h != nil {
		h.broadcast(f)
	}
	if e != nil {
		e(f)
	}
}

func snapshot() []Finding {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Finding, len(findings))
	copy(out, findings)
	return out
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func intersection(a, b []string) []string {
	m := make(map[string]bool, len(b))
	for _, x := range b {
		m[x] = true
	}
	seen := make(map[string]bool)
	var out []string
	for _, x := range a {
		if m[x] && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
