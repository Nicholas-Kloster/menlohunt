package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

// fibonacci — O(n) iterative, O(1) space, no stack risk.
func fibonacci(k int) int {
	if k <= 1 {
		return 1
	}
	a, b := 1, 1
	for i := 2; i <= k; i++ {
		a, b = b, a+b
	}
	return b
}

// fibDelay maps attempt index to a backoff duration.
// k=0→100ms  k=1→100ms  k=2→200ms  k=3→300ms  k=4→500ms …
func fibDelay(k int) time.Duration {
	return time.Duration(fibonacci(k)) * 100 * time.Millisecond
}

// retryGet performs an HTTP GET with fibonacci backoff.
// Retries only on connection failure (0), 429, or 503.
func retryGet(client *http.Client, url string, maxRetries int) (int, string, http.Header) {
	for attempt := 0; attempt <= maxRetries; attempt++ {
		status, body, hdrs := get(client, url)
		switch status {
		case 0, 429, 503:
			if attempt < maxRetries {
				d := fibDelay(attempt)
				fmt.Fprintf(os.Stderr, "[retry] %s — attempt %d/%d, waiting %s\n",
					url, attempt+1, maxRetries, d)
				time.Sleep(d)
			}
		default:
			return status, body, hdrs
		}
	}
	return 0, "", nil
}
