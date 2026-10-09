package vpn

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Profile is passed only through a private pipe or a protected local file.
type Profile struct {
	Address      string `json:"address"`
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key"`
	Endpoint     string `json:"endpoint"`
}

func key(s string) (string, error) {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != 32 {
		return "", errors.New("invalid WireGuard key (expected 32-byte Base64)")
	}
	return hex.EncodeToString(b), nil
}
func (p Profile) Validate() error {
	a, e := netip.ParseAddr(p.Address)
	if e != nil || !a.Is4() {
		return errors.New("VPN address must be IPv4")
	}
	if _, e = netip.ParseAddrPort(p.Endpoint); e != nil {
		return errors.New("VPN endpoint must be a numeric IP:port")
	}
	for _, s := range []string{p.PrivateKey, p.PublicKey, p.PresharedKey} {
		if _, e = key(s); e != nil {
			return e
		}
	}
	return nil
}

type Tunnel struct {
	dev *device.Device
	net *netstack.Net
}

func New(p Profile, mtu int) (*Tunnel, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	t, n, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(p.Address)}, nil, mtu)
	if e != nil {
		return nil, e
	}
	d := device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	priv, _ := key(p.PrivateKey)
	pub, _ := key(p.PublicKey)
	psk, _ := key(p.PresharedKey)
	u := fmt.Sprintf("private_key=%s\npublic_key=%s\npreshared_key=%s\nendpoint=%s\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n", priv, pub, psk, p.Endpoint)
	if e = d.IpcSet(u); e != nil {
		d.Close()
		return nil, errors.New("WireGuard configuration rejected")
	}
	if e = d.Up(); e != nil {
		d.Close()
		return nil, e
	}
	return &Tunnel{d, n}, nil
}
func (t *Tunnel) Close() { t.dev.Close() }
func (t *Tunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return t.net.DialContext(ctx, network, address)
}

// Gate has no ordinary-network fallback. Disconnect cancels active flows.
type Gate struct {
	mu     sync.RWMutex
	tunnel *Tunnel
	ctx    context.Context
	cancel context.CancelFunc
}

func (g *Gate) Set(t *Tunnel) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cancel != nil {
		g.cancel()
	}
	if g.tunnel != nil {
		g.tunnel.Close()
	}
	g.tunnel = t
	g.ctx, g.cancel = context.WithCancel(context.Background())
}
func (g *Gate) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	g.mu.RLock()
	t, session := g.tunnel, g.ctx
	g.mu.RUnlock()
	if t == nil {
		return nil, errors.New("university VPN is disconnected")
	}
	joined, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(session, cancel)
	defer stop()
	c, e := t.DialContext(joined, network, address)
	if e != nil {
		return nil, e
	}
	// Close the socket when the authenticated tunnel is withdrawn.
	end := context.AfterFunc(session, func() { c.Close() })
	return &gatedConn{Conn: c, stop: end, session: session}, nil
}

type gatedConn struct {
	net.Conn
	stop    func() bool
	session context.Context
}

func (c *gatedConn) SessionContext() context.Context { return c.session }

func (c *gatedConn) Close() error { c.stop(); return c.Conn.Close() }
func (c *gatedConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}
