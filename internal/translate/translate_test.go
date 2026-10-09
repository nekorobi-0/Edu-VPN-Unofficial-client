package translate

import (
	"context"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type testDial struct {
	tcp, udp string
	seen     chan string
	session  context.Context
	mu       sync.RWMutex
}

type testSessionConn struct {
	net.Conn
	ctx context.Context
}

func (c *testSessionConn) SessionContext() context.Context { return c.ctx }

func (d *testDial) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	d.seen <- n + " " + a
	if n == "tcp" {
		a = d.tcp
	} else {
		a = d.udp
	}
	c, e := (&net.Dialer{}).DialContext(ctx, n, a)
	d.mu.RLock()
	session := d.session
	d.mu.RUnlock()
	if e == nil && session != nil {
		return &testSessionConn{c, session}, nil
	}
	return c, e
}
func TestIPv6PacketsToIPv4TCPAndUDP(t *testing.T) {
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
	g, e := New(netip.MustParsePrefix("fd00:596e:7500::/96"), d, 1280)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	ct, cn, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("fd00:596e:7501::2")}, nil, 1280)
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
		c, e := cn.DialContext(ctx, n, "[fd00:596e:7500::cb00:7107]:"+strconv.Itoa(8080+i))
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		msg := []byte("NAT64 " + n)
		if _, e = c.Write(msg); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, len(msg))
		if _, e = io.ReadFull(c, b); e != nil {
			t.Fatal(e)
		}
		if string(b) != string(msg) {
			t.Fatal("corrupt relay")
		}
		c.Close()
		select {
		case dst := <-d.seen:
			if !strings.HasPrefix(dst, n+" 203.0.113.7:") {
				t.Fatalf("wrong translated destination %s", dst)
			}
		case <-ctx.Done():
			t.Fatal("no IPv4 dial")
		}
	}
	withdraw, closeSession := context.WithCancel(context.Background())
	d.mu.Lock()
	d.session = withdraw
	d.mu.Unlock()
	c, e := cn.DialContext(ctx, "tcp", "[fd00:596e:7500::cb00:7107]:8090")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.Write([]byte("x"))
	b := make([]byte, 1)
	c.SetDeadline(time.Now().Add(time.Second))
	if _, e = c.Read(b); e != nil {
		t.Fatal(e)
	}
	closeSession()
	if _, e = c.Read(b); e == nil {
		t.Fatal("session withdrawal did not close client TCP flow")
	}
}
func TestClosePacketsDoNotStartSessions(t *testing.T) {
	p := make([]byte, 60)
	p[0] = 0x60
	p[5] = 20
	p[6] = 6
	p[52] = 5 << 4
	for _, flags := range []byte{0x10, 0x11, 0x14} {
		p[53] = flags
		if useful(p, true) || useful(p, false) {
			t.Fatal("closing/control packet counts as activity")
		}
	}
	p[53] = 2
	if !useful(p, true) || useful(p, false) {
		t.Fatal("client SYN must start authentication")
	}
}
