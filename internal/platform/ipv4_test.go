package platform

import (
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"testing"
)

func TestControlPlaneBypassIsScopedAndRemoved(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux route command expectations")
	}
	var calls []string
	b := &IPv4Bypass{name: "ynu64", dev: "eth0", gateway: "192.0.2.1", ranges: []netip.Prefix{netip.MustParsePrefix("133.34.0.0/16")}, installed: make(map[netip.Addr]func()), execute: func(n string, args ...string) (string, error) {
		calls = append(calls, n+" "+strings.Join(args, " "))
		return "", nil
	}}
	if e := b.Ensure(netip.MustParseAddr("203.0.113.7")); e != nil || len(calls) != 0 {
		t.Fatal("uncaptured endpoint modified routing")
	}
	if e := b.Ensure(netip.MustParseAddr("2001:db8::1")); e != nil || len(calls) != 0 {
		t.Fatal("IPv6 control endpoint should bypass IPv4 route handling")
	}
	ip := netip.MustParseAddr("133.34.1.1")
	if e := b.Ensure(ip); e != nil {
		t.Fatal(e)
	}
	if e := b.Ensure(ip); e != nil {
		t.Fatal(e)
	}
	if len(calls) != 1 || calls[0] != "ip -4 route add 133.34.1.1/32 via 192.0.2.1 dev eth0" {
		t.Fatal("bypass route not pinned to ordinary interface")
	}
	b.Close()
	if len(calls) != 2 || calls[1] != "ip -4 route del 133.34.1.1/32 via 192.0.2.1 dev eth0" {
		t.Fatal("bypass cleanup incorrect")
	}
}
func TestBypassCollisionNeverUsesTun(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux route collision detection")
	}
	for _, dev := range []string{"eth0", "ynu64"} {
		b := &IPv4Bypass{name: "ynu64", dev: "eth0", ranges: []netip.Prefix{netip.MustParsePrefix("133.34.0.0/16")}, installed: make(map[netip.Addr]func()), execute: func(_ string, args ...string) (string, error) {
			if len(args) > 2 && args[2] == "add" {
				return "", errors.New("existing route")
			}
			return `[{"dev":"` + dev + `"}]`, nil
		}}
		e := b.Ensure(netip.MustParseAddr("133.34.1.1"))
		if (e == nil) != (dev == "eth0") {
			t.Fatalf("control-plane route collision on %s mishandled", dev)
		}
		if len(b.installed) != 0 {
			t.Fatal("pre-existing route claimed for cleanup")
		}
	}
}
