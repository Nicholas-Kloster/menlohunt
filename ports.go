package main

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

var portList = []portDef{
	{22, "SSH", Low, []string{"ssh", "remote-access"}},
	{80, "HTTP", Info, []string{"http"}},
	{443, "HTTPS", Info, []string{"https"}},
	{1433, "MSSQL", High, []string{"database", "mssql"}},
	{2375, "Docker Daemon (plaintext)", Critical, []string{"docker", "rce"}},
	{2376, "Docker Daemon (TLS)", High, []string{"docker", "container"}},
	{3000, "Grafana", Medium, []string{"grafana", "observability"}},
	{3306, "MySQL / Cloud SQL", High, []string{"database", "mysql"}},
	{4040, "Spark UI", Medium, []string{"spark", "ml"}},
	{4848, "GlassFish Admin", High, []string{"admin", "java"}},
	{5000, "Docker Registry / dev server", High, []string{"registry", "container"}},
	{5432, "PostgreSQL / Cloud SQL", High, []string{"database", "postgres"}},
	{5601, "Kibana", Medium, []string{"kibana", "observability"}},
	{6379, "Redis", Critical, []string{"redis", "rce"}},
	{6443, "Kubernetes API Server", High, []string{"kubernetes", "k8s"}},
	{8001, "Kubernetes Dashboard", Critical, []string{"kubernetes", "dashboard"}},
	{8080, "HTTP Alt", Medium, []string{"http"}},
	{8082, "redge catalog-sync", Medium, []string{"redge", "menlorecast", "metrics"}},
	{8086, "redge consul-template-aggregator", Medium, []string{"redge", "menlorecast", "wireguard"}},
	{8443, "HTTPS Alt / K8s", Medium, []string{"https", "kubernetes"}},
	{8888, "Jupyter Notebook", Critical, []string{"jupyter", "rce", "ml"}},
	{9000, "MinIO / Portainer", High, []string{"minio", "storage"}},
	{9090, "Prometheus", Medium, []string{"metrics", "observability"}},
	{9200, "Elasticsearch", Critical, []string{"elasticsearch", "database"}},
	{9300, "Elasticsearch transport", High, []string{"elasticsearch"}},
	{10250, "Kubelet API", Critical, []string{"kubernetes", "kubelet", "rce"}},
	{10255, "Kubelet read-only", High, []string{"kubernetes", "kubelet"}},
	{11211, "Memcached", High, []string{"memcached", "cache"}},
	{27017, "MongoDB", Critical, []string{"mongodb", "database"}},
}

// redgePorts require a full HTTP GET for detection — their L7 firewall drops
// raw SYN packets that carry no payload.
var redgePorts = map[int]bool{8082: true, 8086: true}

// sortedPorts built once for O(log n) binary search in findPort.
var sortedPorts []portDef

func init() {
	sortedPorts = make([]portDef, len(portList))
	copy(sortedPorts, portList)
	sort.Slice(sortedPorts, func(i, j int) bool {
		return sortedPorts[i].port < sortedPorts[j].port
	})
}

func scanPorts(ip string, timeout time.Duration) map[int]bool {
	open := make(map[int]bool)
	var (
		wg  sync.WaitGroup
		mu2 sync.Mutex
		sem = make(chan struct{}, 50)
	)
	for _, p := range portList {
		wg.Add(1)
		sem <- struct{}{}
		go func(pd portDef) {
			defer wg.Done()
			defer func() { <-sem }()

			var ok bool
			if redgePorts[pd.port] {
				ok = httpOpen(ip, pd.port, timeout)
			} else {
				ok = tcpOpen(ip, pd.port, timeout)
			}
			if !ok {
				return
			}

			mu2.Lock()
			open[pd.port] = true
			mu2.Unlock()

			tags := make([]string, len(pd.tags))
			copy(tags, pd.tags)
			tags = append(tags, "port-scan")
			addFinding(Finding{
				Title:    fmt.Sprintf("Open port %d/tcp — %s", pd.port, pd.service),
				Severity: pd.sev,
				Phase:    "phase1",
				Check:    "port_open",
				Host:     ip,
				Port:     pd.port,
				Proto:    "tcp",
				Evidence: fmt.Sprintf("TCP connect to %s:%d succeeded", ip, pd.port),
				Tags:     tags,
			})
		}(p)
	}
	wg.Wait()
	return open
}

// httpOpen sends a full HTTP GET to detect ports behind L7 firewalls that
// silently drop SYN-only packets (e.g., redge on 8082/8086).
func httpOpen(ip string, port int, timeout time.Duration) bool {
	c := &http.Client{
		Timeout: timeout + 500*time.Millisecond,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
			DisableKeepAlives: true,
		},
	}
	resp, err := c.Get(fmt.Sprintf("http://%s:%d/", ip, port))
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func tcpOpen(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// isPrivateIP uses the stdlib implementation (Go 1.17+) covering all RFC 1918,
// RFC 4193, loopback, and link-local ranges without a manual prefix list.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

func reverseDNS(ip string) []string {
	hosts, _ := net.LookupAddr(ip)
	return hosts
}

func extractNames(ip string, hosts []string) []string {
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.ToLower(strings.TrimSuffix(s, "."))
		if s != "" {
			seen[s] = true
		}
	}
	add(ip)
	for _, h := range hosts {
		add(h)
		for _, part := range strings.Split(h, ".") {
			if len(part) > 3 &&
				part != "compute" && part != "internal" &&
				part != "google" && part != "com" && part != "net" {
				add(part)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}
