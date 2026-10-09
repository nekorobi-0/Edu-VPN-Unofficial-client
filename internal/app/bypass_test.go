package app

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/auth"
)

func TestFailedControlBypassPreventsWireGuardActivation(t *testing.T) {
	s := NewSession(DefaultConfig(), "")
	var called atomic.Int32
	s.BeforeEndpoint = func(netip.Addr) error { called.Add(1); return errors.New("route bypass unavailable") }
	s.source = func(ctx context.Context) <-chan auth.Event {
		ch := make(chan auth.Event, 1)
		ch <- auth.Event{Kind: "profile", Profile: testProfile()}
		go func() { <-ctx.Done(); close(ch) }()
		return ch
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	s.Activity()
	waitState(t, s, "failed", time.Second)
	if called.Load() != 1 {
		t.Fatal("endpoint bypass was not checked")
	}
	if _, e := s.gate.DialContext(context.Background(), "tcp", "133.34.1.1:443"); e == nil {
		t.Fatal("WG activated despite control-route failure")
	}
}
