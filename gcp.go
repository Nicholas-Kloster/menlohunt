package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GCS bucket name patterns — derived from known S3 bucket (redge-d1-usw2-catalog)
// plus generic operator naming conventions.
var gcsBucketPatterns = []string{
	"redge-p1-usw1-catalog", "redge-p1-usw4-catalog",
	"redge-p1-euw2-catalog", "redge-p1-ase1-catalog",
	"redge-d1-usw1-catalog", "redge-d1-usw4-catalog",
	"redge-production-catalog", "menlorecast-catalog",
	"menlorecast-config", "redge-config", "redge-wireguard",
}

// checkGCS probes GCS buckets derived from reverse-DNS names and known patterns.
// HTTP 200 = public read; HTTP 403 = bucket exists but private.
func checkGCS(ip string, names []string, timeout time.Duration) {
	client := newClient(timeout)

	// Per-name candidates (operator naming conventions)
	for _, name := range names {
		candidates := []string{
			name, name + "-backup", name + "-dev", name + "-prod", name + "-data",
		}
		for _, bucket := range candidates {
			probeGCSBucket(client, ip, bucket)
		}
	}

	// Known redge-specific bucket naming patterns
	for _, bucket := range gcsBucketPatterns {
		probeGCSBucket(client, ip, bucket)
	}
}

func probeGCSBucket(client *http.Client, ip, bucket string) {
	url := fmt.Sprintf("https://storage.googleapis.com/%s", bucket)
	status, body, _ := get(client, url)
	switch status {
	case 200:
		addFinding(Finding{
			Title:    "Public GCS bucket — unauthenticated read access",
			Severity: High,
			Phase:    "phase4",
			Check:    "gcs_public",
			Host:     ip,
			URL:      url,
			Evidence: fmt.Sprintf("HTTP 200: %s", trunc(body, 300)),
			Tags:     []string{"gcs", "storage", "public-bucket", "data-exposure"},
		})
	case 403:
		if strings.Contains(body, "does not have storage.objects.list access") ||
			strings.Contains(body, "AccessDenied") ||
			strings.Contains(body, "storage.objects") {
			addFinding(Finding{
				Title:    "GCS bucket exists — access denied (enumerable)",
				Severity: Low,
				Phase:    "phase4",
				Check:    "gcs_exists",
				Host:     ip,
				URL:      url,
				Evidence: "HTTP 403: bucket confirmed to exist",
				Tags:     []string{"gcs", "storage", "bucket-enum"},
			})
		}
	}
}

// checkFirebase probes Firebase Realtime Database endpoints for public read.
func checkFirebase(names []string, timeout time.Duration) {
	client := newClient(timeout)
	for _, name := range names {
		url := fmt.Sprintf("https://%s.firebaseio.com/.json", name)
		status, body, _ := get(client, url)
		if status == 200 && body != "null" && body != "" {
			addFinding(Finding{
				Title:    "Firebase Realtime Database — public read confirmed",
				Severity: Critical,
				Phase:    "phase4",
				Check:    "firebase_public",
				URL:      url,
				Evidence: fmt.Sprintf("HTTP 200: %s", trunc(body, 400)),
				Tags:     []string{"firebase", "database", "unauth", "data-exposure"},
			})
		}
	}
}

// checkMetadataAPI probes the GCP Compute metadata endpoint.
// From an external IP this should never respond — a hit means SSRF or a
// misconfigured proxy is forwarding the Metadata-Flavor header.
func checkMetadataAPI(ip string, timeout time.Duration) {
	client := newClient(timeout)
	endpoints := []struct {
		path  string
		title string
		sev   Severity
	}{
		{"/computeMetadata/v1/?recursive=true", "GCP Metadata API — full instance metadata", Critical},
		{"/computeMetadata/v1/instance/service-accounts/default/token", "GCP Metadata API — SA token exposed", Critical},
		{"/computeMetadata/v1/project/project-id", "GCP Metadata API — project ID exposed", High},
		{"/computeMetadata/v1/instance/hostname", "GCP Metadata API — hostname exposed", Medium},
	}
	for _, ep := range endpoints {
		url := fmt.Sprintf("http://%s%s", ip, ep.path)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Metadata-Flavor", "Google")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == 200 && len(body) > 0 {
			addFinding(Finding{
				Title:    ep.title,
				Severity: ep.sev,
				Phase:    "phase4",
				Check:    "gcp_metadata",
				Host:     ip,
				URL:      url,
				Evidence: trunc(string(body), 400),
				Tags:     []string{"gcp", "metadata-api", "iam", "credentials"},
			})
		}
	}
}

// checkCloudRunFunctions probes common Cloud Run / Cloud Functions URL patterns.
func checkCloudRunFunctions(names []string, timeout time.Duration) {
	client := newClient(timeout)
	regions := []string{"us-central1", "us-east1", "us-west1", "europe-west1", "asia-east1"}
	for _, name := range names {
		for _, region := range regions {
			url := fmt.Sprintf("https://%s-%s.cloudfunctions.net/", name, region)
			status, body, _ := get(client, url)
			if status == 200 && strings.Contains(body, "function") {
				addFinding(Finding{
					Title:    "Cloud Function endpoint accessible unauthenticated",
					Severity: High,
					Phase:    "phase4",
					Check:    "cloud_function_unauth",
					URL:      url,
					Evidence: fmt.Sprintf("HTTP 200: %s", trunc(body, 200)),
					Tags:     []string{"cloud-functions", "gcp", "unauth"},
				})
			}
		}
	}
}
