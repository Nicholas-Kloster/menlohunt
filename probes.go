package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

func checkRedis(ip string, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:6379", ip), timeout)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	conn.Write([]byte("PING\r\n"))
	buf := make([]byte, 128)
	n, _ := conn.Read(buf)
	resp := strings.TrimSpace(string(buf[:n]))

	if !strings.HasPrefix(resp, "+PONG") && !strings.HasPrefix(resp, "+") {
		return
	}
	addFinding(Finding{
		Title:    "Redis unauthenticated — PING/PONG confirmed",
		Severity: Critical,
		Phase:    "phase2",
		Check:    "redis_unauth",
		Host:     ip,
		Port:     6379,
		Proto:    "tcp",
		Evidence: fmt.Sprintf("Server replied: %q", resp),
		Tags:     []string{"redis", "unauth", "rce", "data-exposure"},
	})

	conn.Write([]byte("INFO server\r\n"))
	infoBuf := make([]byte, 2048)
	m, _ := conn.Read(infoBuf)
	info := string(infoBuf[:m])
	if strings.Contains(info, "redis_version") {
		addFinding(Finding{
			Title:    "Redis INFO server — version and config exposed",
			Severity: High,
			Phase:    "phase2",
			Check:    "redis_info",
			Host:     ip,
			Port:     6379,
			Evidence: trunc(info, 400),
			Tags:     []string{"redis", "unauth", "info-disclosure"},
		})
	}
}

func checkMemcached(ip string, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:11211", ip), timeout)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	conn.Write([]byte("stats\r\n"))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])

	if strings.Contains(resp, "STAT ") {
		addFinding(Finding{
			Title:    "Memcached unauthenticated — stats command succeeded",
			Severity: High,
			Phase:    "phase2",
			Check:    "memcached_unauth",
			Host:     ip,
			Port:     11211,
			Evidence: trunc(resp, 400),
			Tags:     []string{"memcached", "unauth", "info-disclosure"},
		})
	}
}

func checkMongoDB(ip string, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:27017", ip), timeout)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Minimal MongoDB OP_MSG isMaster — 58 bytes per wire protocol spec.
	hello := []byte{
		0x3a, 0x00, 0x00, 0x00, // messageLength = 58
		0x01, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xd4, 0x07, 0x00, 0x00, // opCode = OP_MSG (2004)
		0x00, 0x00, 0x00, 0x00, // flagBits
		0x00,                   // section kind = body
		0x13, 0x00, 0x00, 0x00, // BSON doc length
		0x10, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00,
	}
	conn.Write(hello)

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])

	// Require recognizable MongoDB protocol fields — not just any n>20 response.
	if strings.Contains(resp, "ismaster") || strings.Contains(resp, "maxWireVersion") ||
		strings.Contains(resp, "isMaster") || strings.Contains(resp, "topologyVersion") {
		addFinding(Finding{
			Title:    "MongoDB responding unauthenticated",
			Severity: Critical,
			Phase:    "phase2",
			Check:    "mongodb_unauth",
			Host:     ip,
			Port:     27017,
			Evidence: fmt.Sprintf("Wire protocol response (%d bytes): %s", n, trunc(resp, 200)),
			Tags:     []string{"mongodb", "database", "unauth", "data-exposure"},
		})
	}
}

func runProbes(ip string, openPorts map[int]bool, timeout time.Duration) {
	if openPorts[6379] {
		checkRedis(ip, timeout)
	}
	if openPorts[11211] {
		checkMemcached(ip, timeout)
	}
	if openPorts[27017] {
		checkMongoDB(ip, timeout)
	}
}
