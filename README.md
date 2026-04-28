# menlohunt

### "Cloud security is broken if you only look from the inside."

Most Cloud Security Posture Management (CSPM) tools require administrative access: IAM credentials, service accounts, or agents. They tell you what your configuration says—**not what an attacker actually sees.**

**menlohunt** starts where an attacker starts: an IP address and nothing else. It provides a zero-knowledge, "Outside-In" perspective of your Google Cloud Platform (GCP) perimeter.

**No credentials. No agent. No cloud account required. Just an IP and fifteen seconds.**

---

## Why menlohunt?

If you rely solely on internal dashboards, you are operating with **"Insider Bias."** **menlohunt** exists to solve three critical problems:

### 1. Verification of the "Perimeter Illusion"
Firewall rules are complex. Between Hierarchical policies, Network Tags, and Load Balancer proxy rules, what your console says is "closed" might actually be reachable. **menlohunt** doesn't look at your rules; it tries to walk through the door. It provides the **ground-truth** of your exposure.

### 2. Discovering "Connective Tissue"
Traditional scanners look at one IP in a vacuum. **menlohunt** extracts name candidates from TLS certificates and Reverse DNS to pivot. If it finds a project name on a certificate, it immediately probes for related GCS buckets or Firebase databases that belong to that project but aren't hosted on that IP.

### 3. Cutting Through "Alert Fatigue"
Standard scanners bury you in a PDF of 400 "Medium" severity findings. **menlohunt** uses a **mathematical subset sum algorithm** to correlate findings. It recognizes that five "Low" findings sharing a `kubernetes` tag aren't noise—they are a high-priority **Attack Chain**.

---

## Key Features

- **GCP-Native Intelligence:** Purpose-built for GCP. It distinguishes between standard 403s and public-but-restricted GCS/Firebase endpoints. It knows the signatures of the GCP Metadata API and Cloud Run URLs.
- **Attack Chain Discovery:** Automatically groups 2-4 correlated findings into viable attack paths using mathematical scoring.
- **Ultra-Lightweight:** A single 10MB Go binary. Zero dependencies. No 500MB template repos or Python runtimes.
- **Speed:** Executes a five-phase scan (Ports, Protocols, HTTP, TLS, and GCP Surface) in roughly 15 seconds.
- **Air-Gapped & Portable:** Designed to fit in a recon directory. JSON-ready for SIEM pipelines (Splunk, ELK).

---

## The Five-Phase Scan

1.  **Port Discovery:** L7-aware TCP probing that identifies ports even behind "silent" cloud firewalls.
2.  **Protocol Probes:** Raw wire-protocol interaction with Redis, MongoDB, and Memcached to confirm unauthenticated access.
3.  **HTTP Fingerprinting:** Optimized path-grouping checks for Kubelets, Docker Daemons, MLflow, and more.
4.  **TLS Analysis:** Extracts internal IP leaks and GCP project identifiers from Subject Alternative Names (SAN).
5.  **GCP Surface Checks:** Active probing for exposed Metadata APIs, GCS buckets, and Firebase databases using discovered name candidates.

---

## Installation

Built with Go. No external dependencies.

```bash
git clone https://github.com/Nicholas-Kloster/menlohunt
cd menlohunt
go build -o menlohunt *.go
```

## Usage

### 1. Scan a target
```bash
./menlohunt scan -ip 34.120.X.X -out report.json
```

### 2. Generate a human-readable report
```bash
./menlohunt report -in report.json
```

### 3. Search and Filter
```bash
# Search for anything related to "docker"
./menlohunt search -in report.json -q docker

# Filter for Critical vulnerabilities
./menlohunt search -in report.json -sev CRITICAL
```

---

## How Attack Chaining Works

An open SSH port is a `LOW` severity finding. A leaked internal IP is `MEDIUM`.

**menlohunt** recognizes that if they share the same host and a "remote-access" tag, they represent a correlated path. The tool uses a subset sum threshold (default 15) to surface these chains, transforming a flat list of noise into a prioritized list of breaches-in-waiting.

## For the Red & Blue Teams
- **Red Teams:** Use it for "first-strike" recon. Map the attack surface in seconds without triggering heavy internal IAM-based alarms.
- **Blue Teams:** Use it for "Trust but Verify." Prove to stakeholders that your "internal-only" services are actually hidden from the public internet.

---
*Disclaimer: This tool is for authorized security auditing and educational purposes only.*
