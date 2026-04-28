package main

import (
	"log"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var (
	icmpEnabled    atomic.Bool
	icmpPrivileged atomic.Bool
)

const icmpProto = 1 // ICMPv4

func initICMP() {
	// Try unprivileged first (Linux ≥3.x; requires ping_group_range to include our GID)
	if c, err := icmp.ListenPacket("udp4", ""); err == nil {
		c.Close()
		icmpEnabled.Store(true)
		log.Println("[icmp] unprivileged ICMP enabled")
		return
	}
	// Fallback: raw socket (root or CAP_NET_RAW)
	if c, err := icmp.ListenPacket("ip4:icmp", ""); err == nil {
		c.Close()
		icmpEnabled.Store(true)
		icmpPrivileged.Store(true)
		log.Println("[icmp] privileged ICMP enabled (CAP_NET_RAW)")
		return
	}
	log.Println("[icmp] unavailable — host pre-filter disabled\n" +
		"       enable with: sudo sysctl net.ipv4.ping_group_range='0 2147483647'")
}

// icmpAlive returns true if the host responds to an ICMP echo within 350ms,
// or true (pass-through) if ICMP is unavailable. Never returns a false negative.
func icmpAlive(ip string) bool {
	if !icmpEnabled.Load() {
		return true
	}
	network := "udp4"
	if icmpPrivileged.Load() {
		network = "ip4:icmp"
	}
	c, err := icmp.ListenPacket(network, "")
	if err != nil {
		return true
	}
	defer c.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: 0xdead & 0xffff, Seq: 1, Data: []byte("mh")},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return true
	}
	c.SetDeadline(time.Now().Add(350 * time.Millisecond))

	var dst net.Addr
	if icmpPrivileged.Load() {
		dst = &net.IPAddr{IP: net.ParseIP(ip)}
	} else {
		dst = &net.UDPAddr{IP: net.ParseIP(ip)}
	}
	if _, err = c.WriteTo(b, dst); err != nil {
		return true
	}
	rb := make([]byte, 1500)
	for {
		n, _, err := c.ReadFrom(rb)
		if err != nil {
			return false
		}
		payload := rb[:n]
		if icmpPrivileged.Load() && n > 20 {
			payload = rb[20:n]
		}
		rm, err := icmp.ParseMessage(icmpProto, payload)
		if err != nil {
			continue
		}
		if rm.Type == ipv4.ICMPTypeEchoReply {
			return true
		}
	}
}
