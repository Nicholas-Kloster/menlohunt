package main

import (
	"encoding/binary"
	"net"
	"time"
)

// WireGuard UDP ports — standard + common alternates.
var wgPorts = []int{51820, 51821, 51819}

// wgProbe sends a 148-byte Noise HandshakeInitiation to ip:port/UDP.
//
// WireGuard validates MAC1 before responding, so a well-behaved peer silently
// drops malformed initiations. The signal is in the error type:
//   - timeout         → port is open or filtered (potential WireGuard endpoint)
//   - immediate error → ICMP port-unreachable (nothing listening)
//
// Only meaningful when the host is known alive (pair with icmpAlive).
// False-positive rate is high in isolation; use as a candidate filter only.
//
// Noise Initiator layout (WireGuard spec §5.4.2), 148 bytes:
//
//	[0]     type = 1 (HandshakeInitiation)
//	[1-3]   reserved
//	[4-7]   sender_index (randomised from clock)
//	[8-39]  unencrypted_ephemeral (32B, zeroed → invalid)
//	[40-87] encrypted_static (48B)
//	[88-115] encrypted_timestamp (28B)
//	[116-131] MAC1 (16B)
//	[132-147] MAC2 (16B)
func wgProbe(ip string, port int) bool {
	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	var pkt [148]byte
	pkt[0] = 1
	binary.BigEndian.PutUint32(pkt[4:8], uint32(time.Now().UnixNano()))

	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(pkt[:]); err != nil {
		return false
	}
	var resp [256]byte
	_, err = conn.Read(resp[:])
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true // open or filtered
		}
		return false // ICMP unreachable → port closed
	}
	return true // got actual response
}
