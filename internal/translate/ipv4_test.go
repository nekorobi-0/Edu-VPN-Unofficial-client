package translate

import (
	"context"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func TestRealIPv4CIDRForwardingAndIsolation(t *testing.T) {
	tcpL, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer tcpL.Close()
	go func() {
		for {
			c, e := tcpL.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udpL, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udpL.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, p, e := udpL.ReadFrom(b)
			if e != nil {
				return
			}
			udpL.WriteTo(b[:n], p)
		}
	}()
	d := &testDial{tcp: tcpL.Addr().String(), udp: udpL.LocalAddr().String(), seen: make(chan string, 8)}
	g, e := NewWithRoutes(netip.MustParsePrefix("fd00:596e:7500::/96"), d, 1280, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, true)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	for _, a := range []string{"198.51.100.1", "fd00:596e:7500::cb00:7107"} {
		if _, e = g.realDestination(netip.MustParseAddr(a)); e == nil {
			t.Fatalf("IP-only destination isolation failed: %s", a)
		}
	}
	ct, cn, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("198.18.0.1")}, nil, 1280)
	if e != nil {
		t.Fatal(e)
	}
	defer ct.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		b := [][]byte{make([]byte, 65535)}
		sizes := []int{0}
		for {
			n, e := ct.Read(b, sizes, 0)
			if e != nil {
				return
			}
			if n > 0 {
				g.Inject(b[0][:sizes[0]])
			}
		}
	}()
	go func() {
		for {
			p := g.Read(ctx)
			if p == nil {
				return
			}
			if _, e := ct.Write([][]byte{p}, 0); e != nil {
				return
			}
		}
	}()
	for i, n := range []string{"tcp", "udp"} {
		address := "203.0.113.7:" + strconv.Itoa(9090+i)
		c, e := cn.DialContext(ctx, n, address)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		message := []byte("direct IPv4 " + n)
		c.Write(message)
		b := make([]byte, len(message))
		if _, e := io.ReadFull(c, b); e != nil || string(b) != string(message) {
			t.Fatalf("IPv4 %s forwarding failed: %v", n, e)
		}
		c.Close()
		if got := <-d.seen; got != n+" "+address {
			t.Fatal("IPv4 destination changed")
		}
	}
	// Excluded packets must not dial or start authentication.
	excluded, e := NewWithRoutes(netip.MustParsePrefix("fd00:596e:7500::/96"), d, 1280, []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, true)
	if e != nil {
		t.Fatal(e)
	}
	defer excluded.Close()
	activity := 0
	excluded.Activity = func() { activity++ }
	p := make([]byte, 28)
	p[0] = 0x45
	p[3] = 28
	p[9] = 17
	copy(p[16:20], []byte{198, 51, 100, 1})
	excluded.Inject(p)
	if activity != 0 {
		t.Fatal("excluded IPv4 packet triggered authentication")
	}
	select {
	case got := <-d.seen:
		t.Fatalf("excluded destination forwarded: %s", got)
	default:
	}
}
func TestIPv4ActivityParsing(t *testing.T) {
	p := make([]byte, 40)
	p[0] = 0x45
	p[3] = 40
	p[9] = 6
	p[32] = 5 << 4
	p[33] = 0x11
	if useful(p, true) || useful(p, false) {
		t.Fatal("IPv4 FIN/ACK restarts authentication")
	}
	p[33] = 2
	if !useful(p, true) {
		t.Fatal("IPv4 SYN fails to start authentication")
	}
	p[33] = 0x10
	p = append(p, byte('x'))
	p[3] = 41
	if !useful(p, true) || !useful(p, false) {
		t.Fatal("IPv4 TCP payload fails to renew session")
	}
}
