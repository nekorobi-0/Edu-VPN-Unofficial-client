package vpn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func pair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	p, e := curve25519.X25519(k, curve25519.Basepoint)
	if e != nil {
		t.Fatal(e)
	}
	return k, p
}
func TestUnmodifiedWireGuardEncryptionAndWithdrawal(t *testing.T) {
	sk, sp := pair(t)
	ck, cp := pair(t)
	psk := make([]byte, 32)
	rand.Read(psk)
	st, sn, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.99.0.1")}, nil, 1200)
	if e != nil {
		t.Fatal(e)
	}
	sd := device.NewDevice(st, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer sd.Close()
	if e = sd.IpcSet("private_key=" + hex.EncodeToString(sk) + "\nlisten_port=0\npublic_key=" + hex.EncodeToString(cp) + "\npreshared_key=" + hex.EncodeToString(psk) + "\nallowed_ip=10.99.0.2/32\n"); e != nil {
		t.Fatal(e)
	}
	if e = sd.Up(); e != nil {
		t.Fatal(e)
	}
	ipc, e := sd.IpcGet()
	if e != nil {
		t.Fatal(e)
	}
	port := ""
	for _, l := range strings.Split(ipc, "\n") {
		if strings.HasPrefix(l, "listen_port=") {
			port = strings.TrimPrefix(l, "listen_port=")
		}
	}
	if port == "" || port == "0" {
		t.Fatal("no WireGuard listening port")
	}
	listener, e := sn.ListenTCPAddrPort(netip.MustParseAddrPort("10.99.0.1:8080"))
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		c, e := listener.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	tunnel, e := New(Profile{Address: "10.99.0.2", PrivateKey: b64(ck), PublicKey: b64(sp), PresharedKey: b64(psk), Endpoint: "127.0.0.1:" + port}, 1200)
	if e != nil {
		t.Fatal(e)
	}
	var g Gate
	g.Set(tunnel)
	defer g.Set(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := g.DialContext(ctx, "tcp", "10.99.0.1:8080")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	message := []byte("WireGuard encrypted round trip")
	c.Write(message)
	buf := make([]byte, len(message))
	if _, e = io.ReadFull(c, buf); e != nil || string(buf) != string(message) {
		t.Fatalf("round trip failed: %v", e)
	}
	g.Set(nil)
	if _, e = c.Read(make([]byte, 1)); e == nil {
		t.Fatal("withdrawn session socket remained open")
	}
	if _, e = g.DialContext(ctx, "tcp", "10.99.0.1:8080"); e == nil {
		t.Fatal("disconnected gate permitted traffic")
	}
}
