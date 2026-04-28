package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

var gcpSANPatterns = []string{
	".googleapis.com", ".googleusercontent.com", ".appspot.com",
	".cloudfunctions.net", ".run.app", ".firebaseapp.com", ".firebaseio.com",
	".gke.io", "cluster.local", "k8s.local",
}

func analyzeTLS(ip string, port int, timeout time.Duration) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp", fmt.Sprintf("%s:%d", ip, port),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return
	}
	cert := certs[0]

	if time.Now().After(cert.NotAfter) {
		addFinding(Finding{
			Title:    "Expired TLS certificate",
			Severity: Medium,
			Phase:    "phase3",
			Check:    "tls_expired",
			Host:     ip,
			Port:     port,
			Evidence: fmt.Sprintf("Expired: %s | CN: %s | Issuer: %s",
				cert.NotAfter.Format("2006-01-02"),
				cert.Subject.CommonName, cert.Issuer.CommonName),
			Tags: []string{"tls", "certificate", "expired"},
		})
	} else if time.Until(cert.NotAfter) < 30*24*time.Hour {
		addFinding(Finding{
			Title:    "TLS certificate expiring within 30 days",
			Severity: Low,
			Phase:    "phase3",
			Check:    "tls_expiring",
			Host:     ip,
			Port:     port,
			Evidence: fmt.Sprintf("Expires: %s | CN: %s",
				cert.NotAfter.Format("2006-01-02"), cert.Subject.CommonName),
			Tags: []string{"tls", "certificate", "expiring"},
		})
	}

	if cert.Issuer.CommonName == cert.Subject.CommonName {
		addFinding(Finding{
			Title:    "Self-signed TLS certificate",
			Severity: Low,
			Phase:    "phase3",
			Check:    "tls_self_signed",
			Host:     ip,
			Port:     port,
			Evidence: fmt.Sprintf("Issuer == Subject: %q", cert.Subject.CommonName),
			Tags:     []string{"tls", "self-signed"},
		})
	}

	// Build allNames without mutating cert.DNSNames (append can modify the
	// underlying array if it has spare capacity).
	allNames := make([]string, len(cert.DNSNames)+1)
	copy(allNames, cert.DNSNames)
	allNames[len(cert.DNSNames)] = cert.Subject.CommonName

	for _, name := range allNames {
		for _, pat := range gcpSANPatterns {
			if strings.Contains(name, pat) {
				addFinding(Finding{
					Title:    "GCP service fingerprinted via TLS SAN/CN",
					Severity: Info,
					Phase:    "phase3",
					Check:    "tls_gcp_fingerprint",
					Host:     ip,
					Port:     port,
					Evidence: fmt.Sprintf("Name %q matches pattern %q", name, pat),
					Tags:     []string{"gcp", "tls", "fingerprint"},
				})
				break
			}
		}
	}

	for _, ipAddr := range cert.IPAddresses {
		if isPrivateIP(ipAddr.String()) {
			addFinding(Finding{
				Title:    "Private IP address leaked in TLS SAN",
				Severity: Medium,
				Phase:    "phase3",
				Check:    "tls_private_ip_san",
				Host:     ip,
				Port:     port,
				Evidence: fmt.Sprintf("Private IP in cert SAN: %s", ipAddr.String()),
				Tags:     []string{"tls", "info-disclosure", "internal-ip"},
			})
		}
	}

	cs := conn.ConnectionState()
	if cs.Version < tls.VersionTLS12 {
		addFinding(Finding{
			Title:    fmt.Sprintf("Weak TLS version: %s", tlsVersionName(cs.Version)),
			Severity: Medium,
			Phase:    "phase3",
			Check:    "tls_weak_version",
			Host:     ip,
			Port:     port,
			Evidence: fmt.Sprintf("Negotiated: %s — TLS 1.2+ required", tlsVersionName(cs.Version)),
			Tags:     []string{"tls", "weak-crypto"},
		})
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

func runTLSChecks(ip string, openPorts map[int]bool, timeout time.Duration) {
	for _, port := range []int{443, 8443, 6443, 2376} {
		if openPorts[port] {
			analyzeTLS(ip, port, timeout)
		}
	}
}
