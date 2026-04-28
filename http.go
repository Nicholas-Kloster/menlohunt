package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func newClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
			DisableKeepAlives:   true,
			MaxIdleConnsPerHost: 1,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func get(client *http.Client, url string) (int, string, http.Header) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, "", nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return resp.StatusCode, string(body), resp.Header
}

// ── HTTP checks ───────────────────────────────────────────────────────────────

type httpCheck struct {
	path     string
	title    string
	sev      Severity
	tags     []string
	detect   func(status int, body string, hdrs http.Header) bool
	evidence func(status int, body string, hdrs http.Header) string
}

var httpChecks = []httpCheck{
	// ── GCP fingerprint ──
	{
		path:  "/",
		title: "GCP Load Balancer / CDN fingerprinted",
		sev:   Info,
		tags:  []string{"gcp", "fingerprint"},
		detect: func(s int, b string, h http.Header) bool {
			return strings.Contains(h.Get("Server"), "Google") ||
				strings.Contains(h.Get("Server"), "gws") ||
				strings.Contains(h.Get("Via"), "google") ||
				h.Get("X-GUploader-UploadID") != "" ||
				h.Get("X-Goog-Storage-Class") != ""
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("Server: %q  Via: %q  X-Cloud-Trace: %q",
				h.Get("Server"), h.Get("Via"), h.Get("X-Cloud-Trace-Context"))
		},
	},
	// ── Kubernetes ──
	{
		path:  "/api/v1/namespaces",
		title: "Kubernetes API — namespaces reachable unauthenticated",
		sev:   Critical,
		tags:  []string{"kubernetes", "k8s", "unauth"},
		detect: func(s int, b string, h http.Header) bool {
			return (s == 200 || s == 403) &&
				(strings.Contains(b, "NamespaceList") || strings.Contains(b, "\"kind\""))
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	{
		path:  "/api/v1/pods",
		title: "Kubernetes API — pod list exposed unauthenticated",
		sev:   Critical,
		tags:  []string{"kubernetes", "k8s", "unauth", "rce"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "PodList")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	{
		path:  "/api/v1/secrets",
		title: "Kubernetes API — secrets endpoint accessible",
		sev:   Critical,
		tags:  []string{"kubernetes", "k8s", "unauth", "credentials"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "SecretList")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	{
		path:  "/.well-known/openid-configuration",
		title: "Kubernetes OIDC discovery endpoint exposed",
		sev:   Medium,
		tags:  []string{"kubernetes", "oidc", "info-disclosure"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "issuer")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	// ── Kubelet ──
	{
		path:  "/pods",
		title: "Kubelet /pods — node workload exposed",
		sev:   Critical,
		tags:  []string{"kubelet", "k8s", "rce"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "\"podIP\"")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	{
		path:  "/exec",
		title: "Kubelet /exec — remote execution endpoint exposed",
		sev:   Critical,
		tags:  []string{"kubelet", "k8s", "rce"},
		detect: func(s int, b string, h http.Header) bool {
			return s != 404 && s != 0
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: kubelet exec endpoint reachable", s)
		},
	},
	// ── Docker ──
	{
		path:  "/v1.24/info",
		title: "Docker daemon API — /info exposed",
		sev:   Critical,
		tags:  []string{"docker", "rce"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "DockerRootDir")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	{
		path:  "/v1.24/images/json",
		title: "Docker daemon API — image list exposed",
		sev:   Critical,
		tags:  []string{"docker", "rce"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "RepoTags")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	{
		path:  "/v1.24/containers/json",
		title: "Docker daemon API — running containers listed",
		sev:   Critical,
		tags:  []string{"docker", "rce", "info-disclosure"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "\"Image\"")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	{
		path:  "/v2/_catalog",
		title: "Docker Registry — image catalog exposed unauthenticated",
		sev:   High,
		tags:  []string{"registry", "container", "unauth"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "repositories")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	// ── Jupyter ──
	{
		path:  "/",
		title: "Jupyter Notebook — no authentication",
		sev:   Critical,
		tags:  []string{"jupyter", "rce", "ml"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && (strings.Contains(b, "Jupyter") ||
				strings.Contains(b, "jupyter_notebook_config") ||
				strings.Contains(b, "ipython"))
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	// ── Prometheus ──
	{
		path:  "/metrics",
		title: "Prometheus /metrics exposed",
		sev:   Medium,
		tags:  []string{"prometheus", "metrics", "info-disclosure"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "# HELP") && strings.Contains(b, "# TYPE")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: Prometheus metrics open — %d bytes", s, len(b))
		},
	},
	// ── redge-specific ─────────────────────────────────────────────────────────
	// Menlo Security "redge" overlay: catalog-sync + consul-template-aggregator
	// expose Prometheus /metrics and Go expvar /debug/vars on ports 8082/8086.
	{
		path:  "/metrics",
		title: "redge — catalog-sync metrics exposed (menlorecast operator)",
		sev:   High,
		tags:  []string{"redge", "menlorecast", "metrics", "info-disclosure", "wireguard"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && (strings.Contains(b, "catalog_sync") ||
				strings.Contains(b, "consul_template") ||
				strings.Contains(b, "renderTemplate") ||
				strings.Contains(b, "menlorecast"))
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: redge metrics leaked (%d bytes)", s, len(b))
		},
	},
	{
		path:  "/debug/vars",
		title: "redge — expvar cmdline: S3 bucket, region, WireGuard config paths",
		sev:   High,
		tags:  []string{"redge", "menlorecast", "info-disclosure", "credentials", "wireguard"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && (strings.Contains(b, "redge") ||
				strings.Contains(b, "catalog") ||
				strings.Contains(b, "wireguard") ||
				strings.Contains(b, "cmdline"))
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 500))
		},
	},
	// ── Elasticsearch ──
	{
		path:  "/_cat/indices?format=json",
		title: "Elasticsearch — indices exposed unauthenticated",
		sev:   Critical,
		tags:  []string{"elasticsearch", "database", "unauth"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "\"index\"")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	{
		path:  "/_cluster/health",
		title: "Elasticsearch — cluster health unauthenticated",
		sev:   High,
		tags:  []string{"elasticsearch", "info-disclosure"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "cluster_name")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 300))
		},
	},
	// ── MinIO ──
	{
		path:  "/",
		title: "MinIO object storage console exposed",
		sev:   High,
		tags:  []string{"minio", "storage", "s3"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && (strings.Contains(b, "MinIO") || strings.Contains(b, "minio"))
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 200))
		},
	},
	// ── Grafana ──
	{
		path:  "/api/health",
		title: "Grafana health endpoint accessible",
		sev:   Low,
		tags:  []string{"grafana", "observability"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "\"database\"")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 200))
		},
	},
	// ── MLflow ──
	{
		path:  "/api/v1/status",
		title: "MLflow tracking server exposed",
		sev:   High,
		tags:  []string{"mlflow", "ml", "info-disclosure"},
		detect: func(s int, b string, h http.Header) bool {
			return s == 200 && strings.Contains(b, "mlflow")
		},
		evidence: func(s int, b string, h http.Header) string {
			return fmt.Sprintf("HTTP %d: %s", s, trunc(b, 200))
		},
	},
}

type cacheEntry struct {
	status int
	body   string
	hdrs   http.Header
}

// checkHTTP fetches each unique path once, then runs all matching detectors
// against the cached response — eliminates duplicate GET requests when multiple
// checks share the same path (e.g., "/" for GCP fingerprint, Jupyter, MinIO).
func checkHTTP(ip string, port int, scheme string, timeout time.Duration, retries int) {
	client := newClient(timeout)
	base := fmt.Sprintf("%s://%s:%d", scheme, ip, port)

	cache := map[string]cacheEntry{}
	for _, chk := range httpChecks {
		if _, seen := cache[chk.path]; !seen {
			status, body, hdrs := retryGet(client, base+chk.path, retries)
			cache[chk.path] = cacheEntry{status, body, hdrs}
		}
	}

	for _, chk := range httpChecks {
		e := cache[chk.path]
		if e.status == 0 {
			continue
		}
		if !chk.detect(e.status, e.body, e.hdrs) {
			continue
		}
		tags := make([]string, len(chk.tags))
		copy(tags, chk.tags)
		f := Finding{
			Title:    chk.title,
			Severity: chk.sev,
			Phase:    "phase2",
			Check:    "http_fingerprint",
			Host:     ip,
			Port:     port,
			URL:      base + chk.path,
			Status:   fmt.Sprintf("%d", e.status),
			Evidence: chk.evidence(e.status, e.body, e.hdrs),
			Tags:     tags,
		}
		if chk.sev >= High {
			hdrs := map[string]string{}
			for k, v := range e.hdrs {
				hdrs[k] = strings.Join(v, ", ")
			}
			f.Headers = hdrs
			f.Body = trunc(e.body, 4096)
		}
		addFinding(f)
	}
}

func runHTTPChecks(ip string, openPorts map[int]bool, timeout time.Duration, retries int) {
	targets := []struct {
		port   int
		scheme string
	}{
		{80, "http"}, {443, "https"}, {8080, "http"}, {8082, "http"}, {8086, "http"},
		{8443, "https"}, {6443, "https"}, {8888, "http"}, {9090, "http"},
		{10250, "https"}, {10255, "http"}, {2375, "http"}, {9200, "http"},
		{5601, "http"}, {3000, "http"}, {8001, "http"}, {9000, "http"}, {5000, "http"},
	}
	var wg sync.WaitGroup
	for _, t := range targets {
		if !openPorts[t.port] {
			continue
		}
		wg.Add(1)
		go func(port int, scheme string) {
			defer wg.Done()
			checkHTTP(ip, port, scheme, timeout, retries)
		}(t.port, t.scheme)
	}
	wg.Wait()
}
