package main

// The first hop is deliberately strict about RFC 1928 §7, like Aether's expected_udp_source.
// Only a single test destination is forwarded, only to the local userspace WireGuard peer.
import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"
)

func testRelay(peer *net.UDPAddr, allow bool) int {
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	must(err)
	go func() {
		for {
			c, err := ln.AcceptTCP()
			if err != nil {
				return
			}
			go handleAssociation(c, peer, allow)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func handleAssociation(c *net.TCPConn, peer *net.UDPAddr, allow bool) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	greeting := make([]byte, 3)
	if _, err := io.ReadFull(c, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 1, 0}) {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	request := make([]byte, 10)
	if _, err := io.ReadFull(c, request); err != nil {
		return
	}
	if !allow || !bytes.Equal(request, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}) {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	defer relay.Close()
	reply := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0} // wildcard BND.ADDR as when Aether shares its listener
	binary.BigEndian.PutUint16(reply[8:], uint16(relay.LocalAddr().(*net.UDPAddr).Port))
	if _, err := c.Write(reply); err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	go func() { var b [1]byte; c.Read(b[:]); relay.Close() }()
	var client *net.UDPAddr
	header := []byte{0, 0, 0, 1, 127, 0, 0, 2, 0, 1}
	packet := make([]byte, 65535)
	for {
		n, from, err := relay.ReadFromUDP(packet)
		if err != nil {
			return
		}
		if from.Port == peer.Port && from.IP.Equal(peer.IP) {
			if client != nil {
				relay.WriteToUDP(append(header[:len(header):len(header)], packet[:n]...), client)
			}
		} else if n > len(header) && from.IP.Equal(net.IPv4(127, 0, 0, 1)) && (client == nil || from.Port == client.Port) && bytes.Equal(packet[:len(header)], header) {
			client = from
			relay.WriteToUDP(packet[len(header):n], peer)
		}
	}
}
