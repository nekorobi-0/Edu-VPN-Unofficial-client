package dns64

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
type Resolver struct {
	Prefix          netip.Prefix
	Domains         []string
	PublicUpstream  string
	CampusUpstreams []string
	CampusDomains   []string
	Tunnel          Dialer
	Timeout         time.Duration
	Activity        func()
	Ready           func(string)
}

func Matches(name string, domains []string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, d := range domains {
		d = strings.ToLower(strings.Trim(d, "."))
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}
func Embed(prefix netip.Prefix, v4 netip.Addr) (netip.Addr, error) {
	if !prefix.Addr().Is6() || prefix.Bits() != 96 || !v4.Is4() {
		return netip.Addr{}, errors.New("DNS64 requires IPv6 /96 and IPv4")
	}
	b := prefix.Masked().Addr().As16()
	v := v4.As4()
	copy(b[12:], v[:])
	return netip.AddrFrom16(b), nil
}
func Extract(prefix netip.Prefix, v6 netip.Addr) (netip.Addr, error) {
	if prefix.Bits() != 96 || !v6.Is6() || !prefix.Contains(v6) {
		return netip.Addr{}, errors.New("destination outside NAT64 prefix")
	}
	b := v6.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), nil
}
func exchange(ctx context.Context, d Dialer, upstream string, packet []byte) ([]byte, error) {
	// TCP avoids truncation and supports large CNAME chains without EDNS negotiation.
	c, e := d.DialContext(ctx, "tcp", upstream)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	b := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(b, uint16(len(packet)))
	copy(b[2:], packet)
	if _, e = c.Write(b); e != nil {
		return nil, e
	}
	if _, e = io.ReadFull(c, b[:2]); e != nil {
		return nil, e
	}
	out := make([]byte, int(binary.BigEndian.Uint16(b[:2])))
	_, e = io.ReadFull(c, out)
	return out, e
}
func (r *Resolver) lookup(ctx context.Context, request dnsmessage.Message, name string) (dnsmessage.Message, error) {
	raw, e := request.Pack()
	if e != nil {
		return dnsmessage.Message{}, e
	}
	d := Dialer(&net.Dialer{})
	ups := []string{r.PublicUpstream}
	if Matches(name, r.CampusDomains) {
		d = r.Tunnel
		ups = r.CampusUpstreams
	}
	for _, u := range ups {
		b, e := exchange(ctx, d, u, raw)
		if e != nil {
			continue
		}
		var m dnsmessage.Message
		if e = m.Unpack(b); e != nil {
			continue
		}
		if !m.Response || m.ID != request.ID || len(m.Questions) != 1 || m.Questions[0] != request.Questions[0] {
			continue
		}
		if m.RCode == dnsmessage.RCodeServerFailure {
			continue
		}
		return m, nil
	}
	return dnsmessage.Message{}, errors.New("DNS upstream unavailable")
}
func (r *Resolver) Answer(ctx context.Context, raw []byte) []byte {
	var q dnsmessage.Message
	if q.Unpack(raw) != nil || q.Response || len(q.Questions) != 1 {
		return nil
	}
	base := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true}, Questions: q.Questions}
	fail := func(code dnsmessage.RCode) []byte { base.RCode = code; b, _ := base.Pack(); return b }
	if q.OpCode != 0 || q.Questions[0].Class != dnsmessage.ClassINET {
		return fail(dnsmessage.RCodeNotImplemented)
	}
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	name := q.Questions[0].Name.String()
	target := Matches(name, r.Domains)
	if target && r.Activity != nil {
		r.Activity()
	}
	// HTTPS/SVCB may carry real ipv4hint/ipv6hint and bypass the synthetic address.
	if target && (q.Questions[0].Type == dnsmessage.TypeA || q.Questions[0].Type == dnsmessage.Type(64) || q.Questions[0].Type == dnsmessage.Type(65) || q.Questions[0].Type == dnsmessage.Type(255)) {
		aq := q
		aq.Questions = append([]dnsmessage.Question(nil), q.Questions...)
		aq.Questions[0].Type = dnsmessage.TypeA
		aq.Additionals = nil
		a, e := r.lookup(ctx, aq, name)
		if e != nil {
			return fail(dnsmessage.RCodeServerFailure)
		}
		return fail(a.RCode) // NOERROR/NODATA preserves NXDOMAIN and fails closed on upstream error.
	}
	if target && q.Questions[0].Type == dnsmessage.TypeAAAA {
		aq := q
		aq.Questions = append([]dnsmessage.Question(nil), q.Questions...)
		aq.Questions[0].Type = dnsmessage.TypeA
		aq.Additionals = nil
		a, e := r.lookup(ctx, aq, name)
		if e != nil {
			return fail(dnsmessage.RCodeServerFailure)
		}
		base.RCode = a.RCode
		hasAddress := false
		for _, rr := range a.Answers {
			switch b := rr.Body.(type) {
			case *dnsmessage.CNAMEResource:
				base.Answers = append(base.Answers, rr)
			case *dnsmessage.AResource:
				hasAddress = true
				ip, e := Embed(r.Prefix, netip.AddrFrom4(b.A))
				if e != nil {
					return fail(dnsmessage.RCodeServerFailure)
				}
				rr.Header.Type = dnsmessage.TypeAAAA
				rr.Body = &dnsmessage.AAAAResource{AAAA: ip.As16()}
				base.Answers = append(base.Answers, rr)
			}
		}
		if !hasAddress {
			base.Answers = nil
		} // A CNAME-only answer could cause a direct external AAAA lookup.
		// No AD flag / RRSIG: locally synthesized answers cannot claim DNSSEC validation.
		b, _ := base.Pack()
		return b
	}
	a, e := r.lookup(ctx, q, name)
	if e != nil {
		return fail(dnsmessage.RCodeServerFailure)
	}
	b, _ := a.Pack()
	return b
}

// Serve supports UDP and TCP and closes both listeners on cancellation.
func (r *Resolver) Serve(ctx context.Context, address string) error {
	tcp, e := net.Listen("tcp", address)
	if e != nil {
		return e
	}
	defer tcp.Close()
	udp, e := net.ListenPacket("udp", tcp.Addr().String())
	if e != nil {
		return e
	}
	defer udp.Close()
	if r.Ready != nil {
		r.Ready(tcp.Addr().String())
	}
	stop := context.AfterFunc(ctx, func() { tcp.Close(); udp.Close() })
	defer stop()
	slots := make(chan struct{}, 128)
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func() {
					defer func() { <-slots }()
					defer c.Close()
					end := context.AfterFunc(ctx, func() { c.Close() })
					defer end()
					for {
						c.SetDeadline(time.Now().Add(10 * time.Second))
						var head [2]byte
						if _, e := io.ReadFull(c, head[:]); e != nil {
							return
						}
						n := int(binary.BigEndian.Uint16(head[:]))
						if n == 0 {
							return
						}
						q := make([]byte, n)
						if _, e := io.ReadFull(c, q); e != nil {
							return
						}
						a := r.Answer(ctx, q)
						if a == nil {
							return
						}
						out := make([]byte, 2+len(a))
						binary.BigEndian.PutUint16(out, uint16(len(a)))
						copy(out[2:], a)
						if _, e := c.Write(out); e != nil {
							return
						}
					}
				}()
			default:
				c.Close()
			}
		}
	}()
	for {
		buf := make([]byte, 4096)
		n, peer, e := udp.ReadFrom(buf)
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
			go func(q []byte, p net.Addr) {
				defer func() { <-slots }()
				a := r.Answer(ctx, q)
				if a == nil {
					return
				}
				if len(a) > 512 {
					var m dnsmessage.Message
					if m.Unpack(a) == nil {
						m.Truncated = true
						m.Answers = nil
						m.Authorities = nil
						m.Additionals = nil
						a, _ = m.Pack()
					}
				}
				udp.WriteTo(a, p)
			}(buf[:n], peer)
		default:
		}
	}
}
