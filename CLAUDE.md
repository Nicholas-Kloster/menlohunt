# menlohunt

GCP External Attack Surface Management (EASM) — zero-knowledge perimeter scanning purpose-built for GCP. Five-phase scan (ports → protocol probes → HTTP fingerprint → TLS analysis → GCP surface checks). Distinguishes standard 403s from public-but-restricted GCS/Firebase, knows GCP Metadata API + Cloud Run signatures, extracts project IDs from TLS SAN, attack-chains 2-4 correlated findings via subset-sum scoring.

## Language
Go (single 10MB binary, zero external dependencies)

## Build & Run
```
go build -o menlohunt *.go

./menlohunt scan -ip 34.120.X.X -out report.json    # 5-phase scan, ~15s
./menlohunt report -in report.json                  # human-readable
./menlohunt search -in report.json -q docker        # substring search
./menlohunt search -in report.json -port 8082       # port-table lookup
./menlohunt sweep -range 34.120.0.0/24              # CIDR sweep with ICMP pre-filter
```

## Layout
```
main.go         # CLI entry + subcommand dispatch
sweep.go        # CIDR sweep with ICMP pre-filter
ports.go        # phase 1 — port discovery
probes.go       # phase 2 — protocol probes (Redis/MongoDB/Memcached)
http.go         # phase 3 — HTTP fingerprinting
tls.go          # phase 4 — TLS analysis + SAN-based pivot candidates
gcp.go          # phase 5 — GCP surface (Metadata API / GCS / Firebase)
icmp.go         # ICMP pre-filter for sweep mode
risk.go         # subset-sum attack-chain scoring
search.go       # report query (substring / severity / port)
dashboard.go    # terminal-rendered scan report
retry.go, types.go, wg.go  # utility primitives
```

## Claude Code Notes
- Check README for the case-study walkthrough (real-world Redge management-plane finding)
- Reports are JSON-shaped — pipe into VisorLog ingest for the broader chain
- Built with [Claude Code](https://claude.ai/code)
