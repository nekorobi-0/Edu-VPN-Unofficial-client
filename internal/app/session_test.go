package app

import (
	"context"
	"encoding/base64"
	"sync/atomic"
	"testing"
	"time"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/auth"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/vpn"
)

func waitState(t *testing.T, s *Session, want string, timeout time.Duration) {
	t.Helper()
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		s.mu.Lock()
		state := s.state
		s.mu.Unlock()
		if state == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Fatalf("wanted %s, got %s", want, s.state)
}
func testProfile() *vpn.Profile {
	k := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return &vpn.Profile{Address: "10.99.0.2", PrivateKey: k, PublicKey: k, PresharedKey: k, Endpoint: "127.0.0.1:1"}
}
func TestOnDemandIdleAndResume(t *testing.T) {
	c := DefaultConfig()
	c.IdleSeconds = 1
	c.AuthTimeoutSeconds = 4
	s := NewSession(c, "")
	var starts, closes atomic.Int32
	s.source = func(ctx context.Context) <-chan auth.Event {
		out := make(chan auth.Event, 1)
		starts.Add(1)
		go func() {
			defer close(out)
			select {
			case <-time.After(1200 * time.Millisecond):
			case <-ctx.Done():
				return
			}
			out <- auth.Event{Kind: "profile", Profile: testProfile()}
			<-ctx.Done()
			closes.Add(1)
		}()
		return out
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	time.Sleep(150 * time.Millisecond)
	if starts.Load() != 0 {
		t.Fatal("eager authentication")
	}
	s.Activity()
	waitState(t, s, "authenticating", time.Second)
	waitState(t, s, "active", 2*time.Second) // auth can exceed idle_seconds
	time.Sleep(600 * time.Millisecond)
	s.Activity()
	time.Sleep(600 * time.Millisecond)
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()
	if state != "active" {
		t.Fatal("traffic did not renew idle timer")
	}
	waitState(t, s, "idle", time.Second)
	if starts.Load() != 1 {
		t.Fatal("idle immediately reopened")
	}
	time.Sleep(100 * time.Millisecond)
	if closes.Load() != 1 {
		t.Fatal("idle did not close auth helper")
	}
	s.Activity()
	waitState(t, s, "authenticating", time.Second)
	if starts.Load() != 2 {
		t.Fatal("new demand did not reauthenticate")
	}
}
func TestCancellationUnblocksWaitingDial(t *testing.T) {
	s := NewSession(DefaultConfig(), "")
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)
	dialctx, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	_, e := s.DialContext(dialctx, "tcp", "133.34.1.1:443")
	if e == nil {
		t.Fatal("disconnected dial escaped to normal network")
	}
	cancel()
}
