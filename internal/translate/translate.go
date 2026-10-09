// Package translate implements a userspace TCP/UDP NAT64 gateway. TCP is
// terminated and relayed, rather than translating TCP headers byte for byte.
package translate

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/dns64"
)

type Gateway struct {
	s        *stack.Stack
	ep       *channel.Endpoint
	prefix   netip.Prefix
	dial     dns64.Dialer
	ctx      context.Context
	cancel   context.CancelFunc
	slots    chan struct{}
	mu       sync.Mutex
	udp      map[stack.TransportEndpointID]bool
	Activity func()
	routes   []netip.Prefix
	ipOnly   bool
}

func New(prefix netip.Prefix, d dns64.Dialer, mtu int) (*Gateway, error) {
	return NewWithRoutes(prefix, d, mtu, nil, false)
}
func NewWithRoutes(prefix netip.Prefix, d dns64.Dialer, mtu int, routes []netip.Prefix, ipOnly bool) (*Gateway, error) {
	if !prefix.Addr().Is6() || prefix.Bits() != 96 {
		return nil, fmt.Errorf("NAT64 prefix must be IPv6 /96")
	}
	ctx, cancel := context.WithCancel(context.Background())
	for _, p := range routes {
		if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 {
			cancel()
			return nil, fmt.Errorf("invalid direct IPv4 route")
		}
	}
	g := &Gateway{prefix: prefix, dial: d, ctx: ctx, cancel: cancel, slots: make(chan struct{}, 1024), udp: make(map[stack.TransportEndpointID]bool), routes: append([]netip.Prefix(nil), routes...), ipOnly: ipOnly}
	g.ep = channel.New(1024, uint32(mtu), "")
	g.s = stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocol, ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4}})
	if e := g.s.CreateNIC(1, g.ep); e != nil {
		g.Close()
		return nil, fmt.Errorf("CreateNIC: %s", e)
	}
	g.s.SetPromiscuousMode(1, true)
	g.s.SetSpoofing(1, true)
	g.s.SetRouteTable([]tcpip.Route{{Destination: header.IPv6EmptySubnet, NIC: 1}, {Destination: header.IPv4EmptySubnet, NIC: 1}})
	f := tcp.NewForwarder(g.s, 0, 128, g.tcp)
	g.s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)
	u := udp.NewForwarder(g.s, g.udpFlow)
	g.s.SetTransportProtocolHandler(udp.ProtocolNumber, u.HandlePacket)
	return g, nil
}
func (g *Gateway) destination(id stack.TransportEndpointID) (string, error) {
	a, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return "", fmt.Errorf("invalid destination")
	}
	ip, e := g.realDestination(a)
	if e != nil {
		return "", e
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip == netip.MustParseAddr("255.255.255.255") {
		return "", fmt.Errorf("invalid translated destination")
	}
	return netip.AddrPortFrom(ip, id.LocalPort).String(), nil
}
func (g *Gateway) realDestination(a netip.Addr) (netip.Addr, error) {
	if a.Is4() {
		for _, p := range g.routes {
			if p.Contains(a) {
				return a, nil
			}
		}
		return netip.Addr{}, fmt.Errorf("IPv4 destination outside configured routes")
	}
	if g.ipOnly {
		return netip.Addr{}, fmt.Errorf("DNS64 disabled in IP-only mode")
	}
	return dns64.Extract(g.prefix, a)
}
func (g *Gateway) take() bool {
	select {
	case g.slots <- struct{}{}:
		return true
	default:
		return false
	}
}
func (g *Gateway) tcp(r *tcp.ForwarderRequest) {
	dst, e := g.destination(r.ID())
	if e != nil || !g.take() {
		r.Complete(true)
		return
	}
	defer func() { <-g.slots }()
	ctx, cancel := context.WithTimeout(g.ctx, 75*time.Second)
	remote, e := g.dial.DialContext(ctx, "tcp", dst)
	cancel()
	if e != nil {
		r.Complete(true)
		return
	}
	defer remote.Close()
	var q waiter.Queue
	ep, te := r.CreateEndpoint(&q)
	if te != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&q, ep)
	defer local.Close()
	stop := context.AfterFunc(g.ctx, func() { local.Close(); remote.Close() })
	defer stop()
	if c, ok := remote.(interface{ SessionContext() context.Context }); ok {
		stopSession := context.AfterFunc(c.SessionContext(), func() { local.Close(); remote.Close() })
		defer stopSession()
	}
	done := make(chan struct{}, 1)
	go func() {
		io.Copy(remote, local)
		if c, ok := remote.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		} else {
			remote.Close()
		}
		done <- struct{}{}
	}()
	io.Copy(local, remote)
	local.CloseWrite()
	<-done
}
func (g *Gateway) udpFlow(r *udp.ForwarderRequest) {
	id := r.ID()
	dst, e := g.destination(id)
	g.mu.Lock()
	duplicate := g.udp[id]
	if !duplicate {
		g.udp[id] = true
	}
	g.mu.Unlock()
	// Endpoint creation must be synchronous so subsequent packets find the flow.
	var q waiter.Queue
	ep, te := r.CreateEndpoint(&q)
	if te != nil {
		if !duplicate {
			g.mu.Lock()
			delete(g.udp, id)
			g.mu.Unlock()
		}
		return
	}
	local := gonet.NewUDPConn(&q, ep)
	if e != nil || duplicate || !g.take() {
		local.Close()
		if !duplicate {
			g.mu.Lock()
			delete(g.udp, id)
			g.mu.Unlock()
		}
		return
	}
	go func() {
		defer func() { local.Close(); g.mu.Lock(); delete(g.udp, id); g.mu.Unlock(); <-g.slots }()
		ctx, cancel := context.WithTimeout(g.ctx, 75*time.Second)
		remote, e := g.dial.DialContext(ctx, "udp", dst)
		cancel()
		if e != nil {
			return
		}
		defer remote.Close()
		stop := context.AfterFunc(g.ctx, func() { local.Close(); remote.Close() })
		defer stop()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer local.Close()
			b := make([]byte, 65535)
			for {
				remote.SetReadDeadline(time.Now().Add(2 * time.Minute))
				n, e := remote.Read(b)
				if e != nil {
					return
				}
				if _, e = local.Write(b[:n]); e != nil {
					return
				}
			}
		}()
		b := make([]byte, 65535)
		for {
			local.SetReadDeadline(time.Now().Add(2 * time.Minute))
			n, e := local.Read(b)
			if e != nil {
				break
			}
			if _, e = remote.Write(b[:n]); e != nil {
				break
			}
		}
		remote.Close()
		<-done
	}()
}
func (g *Gateway) Inject(packet []byte) {
	var dst netip.Addr
	var protocol tcpip.NetworkProtocolNumber
	if len(packet) == 0 {
		return
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 || packet[9] == 1 {
			return
		}
		dst, _ = netip.AddrFromSlice(packet[16:20])
		protocol = header.IPv4ProtocolNumber
	case 6:
		if len(packet) < 40 || packet[6] == 58 {
			return
		}
		dst, _ = netip.AddrFromSlice(packet[24:40])
		protocol = header.IPv6ProtocolNumber
	default:
		return
	}
	if _, e := g.realDestination(dst); e != nil {
		return
	}
	if useful(packet, true) && g.Activity != nil {
		g.Activity()
	}
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	defer p.DecRef()
	g.ep.InjectInbound(protocol, p)
}
func (g *Gateway) Read(ctx context.Context) []byte {
	p := g.ep.ReadContext(ctx)
	if p == nil {
		return nil
	}
	defer p.DecRef()
	v := p.ToView()
	defer v.Release()
	if useful(v.AsSlice(), false) && g.Activity != nil {
		g.Activity()
	}
	return append([]byte(nil), v.AsSlice()...)
}

// Pure ACK/FIN/RST generated while closing a flow must not reopen authentication.
func useful(p []byte, incoming bool) bool {
	if len(p) == 0 {
		return false
	}
	var start, end int
	var proto byte
	switch p[0] >> 4 {
	case 6:
		if len(p) < 40 {
			return false
		}
		start = 40
		end = start + int(binary.BigEndian.Uint16(p[4:6]))
		proto = p[6]
	case 4:
		if len(p) < 20 {
			return false
		}
		start = int(p[0]&15) * 4
		end = int(binary.BigEndian.Uint16(p[2:4]))
		proto = p[9]
		if start < 20 || binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
			return false
		}
	default:
		return false
	}
	if end > len(p) {
		return false
	}
	switch proto {
	case 17:
		return end >= start+8
	case 6:
		if end < start+20 {
			return false
		}
		hdr := int(p[start+12]>>4) * 4
		if hdr < 20 || start+hdr > end {
			return false
		}
		return end > start+hdr || (incoming && p[start+13]&2 != 0 && p[start+13]&16 == 0)
	default:
		return false
	}
}
func (g *Gateway) Close() {
	g.cancel()
	if g.s != nil {
		g.s.Close()
	}
	if g.ep != nil {
		g.ep.Close()
	}
}

// Pump owns the operating-system TUN until cancellation or an I/O failure.
func (g *Gateway) Pump(ctx context.Context, t tun.Device) error {
	stop := context.AfterFunc(ctx, func() { t.Close() })
	defer stop()
	errch := make(chan error, 2)
	go func() {
		bufs := make([][]byte, t.BatchSize())
		sizes := make([]int, len(bufs))
		for i := range bufs {
			bufs[i] = make([]byte, 65535)
		}
		for {
			n, e := t.Read(bufs, sizes, 0)
			if e != nil {
				errch <- e
				return
			}
			for i := 0; i < n; i++ {
				g.Inject(bufs[i][:sizes[i]])
			}
		}
	}()
	go func() {
		for {
			p := g.Read(ctx)
			if p == nil {
				errch <- nil
				return
			}
			if _, e := t.Write([][]byte{p}, 0); e != nil {
				errch <- e
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case e := <-errch:
		return e
	}
}
