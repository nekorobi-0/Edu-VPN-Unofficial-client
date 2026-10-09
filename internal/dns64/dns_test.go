package dns64

import (
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func upstream(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	count := new(atomic.Int32)
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				var b [2]byte
				if _, e := io.ReadFull(c, b[:]); e != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(b[:]))
				io.ReadFull(c, q)
				var m dnsmessage.Message
				if m.Unpack(q) != nil {
					return
				}
				count.Add(1)
				m.Response = true
				m.AuthenticData = true
				if m.Questions[0].Name.String() == "missing.ynu.ac.jp." {
					m.RCode = dnsmessage.RCodeNameError
				} else {
					alias, _ := dnsmessage.NewName("external-cdn.example.")
					m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 37}, Body: &dnsmessage.CNAMEResource{CNAME: alias}}}
					if m.Questions[0].Type == dnsmessage.TypeA {
						m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 37}, Body: &dnsmessage.AResource{A: [4]byte{133, 34, 184, 6}}})
					} else {
						m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 37}, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}})
					}
				}
				out, _ := m.Pack()
				binary.BigEndian.PutUint16(b[:], uint16(len(out)))
				c.Write(b[:])
				c.Write(out)
			}()
		}
	}()
	return l.Addr().String(), count
}
func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	n, _ := dnsmessage.NewName(name)
	b, e := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: typ, Class: dnsmessage.ClassINET}}}).Pack()
	if e != nil {
		t.Fatal(e)
	}
	return b
}

type countDial struct{ n atomic.Int32 }

func (d *countDial) DialContext(c context.Context, n, a string) (net.Conn, error) {
	d.n.Add(1)
	return (&net.Dialer{}).DialContext(c, n, a)
}
func TestDomainIsolationSynthesisAndSuppression(t *testing.T) {
	addr, _ := upstream(t)
	dial := new(countDial)
	var activity atomic.Int32
	r := Resolver{Prefix: netip.MustParsePrefix("fd00:596e:7500::/96"), Domains: []string{"ac.jp"}, CampusDomains: []string{"ynu.ac.jp"}, PublicUpstream: addr, CampusUpstreams: []string{addr}, Tunnel: dial, Activity: func() { activity.Add(1) }}
	for _, tt := range []struct {
		name    string
		typ     dnsmessage.Type
		answers int
		synth   bool
		rcode   dnsmessage.RCode
	}{{"www.ynu.ac.jp.", dnsmessage.TypeAAAA, 2, true, 0}, {"www.ynu.ac.jp.", dnsmessage.TypeA, 0, false, 0}, {"www.ynu.ac.jp.", dnsmessage.Type(65), 0, false, 0}, {"missing.ynu.ac.jp.", dnsmessage.TypeAAAA, 0, false, dnsmessage.RCodeNameError}, {"evilac.jp.", dnsmessage.TypeAAAA, 2, false, 0}, {"www.other.ac.jp.", dnsmessage.TypeAAAA, 2, true, 0}} {
		var m dnsmessage.Message
		if e := m.Unpack(r.Answer(context.Background(), query(t, tt.name, tt.typ))); e != nil {
			t.Fatal(e)
		}
		if m.ID != 42 || len(m.Answers) != tt.answers || m.RCode != tt.rcode {
			t.Fatalf("%s type=%d: bad answer %+v", tt.name, tt.typ, m)
		}
		if tt.synth {
			if m.AuthenticData {
				t.Fatal("synthesized answer claims DNSSEC validation")
			}
			ip := netip.AddrFrom16(m.Answers[1].Body.(*dnsmessage.AAAAResource).AAAA)
			v, e := Extract(r.Prefix, ip)
			if e != nil || v.String() != "133.34.184.6" {
				t.Fatal("bad embedded IPv4")
			}
			if m.Answers[1].Header.TTL != 37 {
				t.Fatal("lost upstream TTL")
			}
		}
	}
	if dial.n.Load() != 4 {
		t.Fatalf("campus lookups escaped VPN: %d", dial.n.Load())
	}
	if activity.Load() != 5 {
		t.Fatalf("non-ac.jp triggered authentication: %d", activity.Load())
	}
}
func TestDNSUnavailableFailsClosed(t *testing.T) {
	r := Resolver{Prefix: netip.MustParsePrefix("fd00:596e:7500::/96"), Domains: []string{"ac.jp"}, PublicUpstream: "127.0.0.1:1", Timeout: 100 * time.Millisecond}
	var m dnsmessage.Message
	m.Unpack(r.Answer(context.Background(), query(t, "x.ac.jp.", dnsmessage.TypeAAAA)))
	if m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("DNS failure did not fail closed")
	}
	if Matches("evilac.jp.", []string{"ac.jp"}) {
		t.Fatal("suffix boundary violation")
	}
}

func TestDNSServiceUDPAndTCPAndPortConflict(t *testing.T) {
	upstream, _ := upstream(t)
	ready := make(chan string, 1)
	r := Resolver{Prefix: netip.MustParsePrefix("fd00:596e:7500::/96"), Domains: []string{"ac.jp"}, PublicUpstream: upstream, Ready: func(a string) { ready <- a }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Serve(ctx, "127.0.0.1:0") }()
	var addr string
	select {
	case addr = <-ready:
	case e := <-done:
		t.Fatal(e)
	case <-time.After(time.Second):
		t.Fatal("DNS service not ready")
	}
	packet := query(t, "web.other.ac.jp.", dnsmessage.TypeAAAA)
	udp, e := net.Dial("udp", addr)
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(time.Second))
	udp.Write(packet)
	out := make([]byte, 512)
	n, e := udp.Read(out)
	if e != nil {
		t.Fatal(e)
	}
	var m dnsmessage.Message
	if e = m.Unpack(out[:n]); e != nil || len(m.Answers) != 2 {
		t.Fatalf("bad UDP answer: %v", e)
	}
	tcpAnswer, e := exchange(context.Background(), &net.Dialer{}, addr, packet)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Unpack(tcpAnswer); e != nil || len(m.Answers) != 2 {
		t.Fatalf("bad TCP answer: %v", e)
	}
	collisionReady := false
	collision := r
	collision.Ready = func(string) { collisionReady = true }
	if e = collision.Serve(context.Background(), addr); e == nil || collisionReady {
		t.Fatal("port conflict signalled readiness")
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS listeners did not shut down")
	}
}
