package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/auth"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/desktop"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/vpn"
)

type Session struct {
	config         Config
	dir            string
	gate           vpn.Gate
	mu             sync.Mutex
	last           time.Time
	state          string
	changed        chan struct{}
	wake           chan struct{}
	source         func(context.Context) <-chan auth.Event
	workerDone     <-chan struct{}
	BeforeEndpoint func(netip.Addr) error
	SIMPath        string
}

func NewSession(c Config, dir string) *Session {
	return &Session{config: c, dir: dir, state: "idle", changed: make(chan struct{}), wake: make(chan struct{}, 1), SIMPath: filepath.Join(dir, "auth", "sim.kkm")}
}
func (s *Session) Activity() {
	s.mu.Lock()
	s.last = time.Now()
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *Session) set(state string) {
	s.mu.Lock()
	if state != s.state {
		s.state = state
		desktop.SetSession(state)
		close(s.changed)
		s.changed = make(chan struct{})
		log.Printf("session: %s", state)
	}
	s.mu.Unlock()
}
func (s *Session) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	s.Activity()
	for {
		s.mu.Lock()
		state, changed := s.state, s.changed
		s.mu.Unlock()
		if state == "active" {
			return s.gate.DialContext(ctx, network, address)
		}
		if state == "failed" {
			return nil, errors.New("VPN authentication failed; waiting for retry")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}
func (s *Session) Run(ctx context.Context) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	defer s.gate.Set(nil)
	var cancel context.CancelFunc
	var events <-chan auth.Event
	var started time.Time
	var retryAt time.Time
	stop := func(state string) {
		if cancel != nil {
			cancel()
			cancel = nil
		}
		events = nil
		s.gate.Set(nil)
		if s.workerDone != nil {
			select {
			case <-s.workerDone:
			case <-time.After(3 * time.Second):
				log.Print("authentication shutdown timed out")
			}
			s.workerDone = nil
		}
		s.set(state)
	}
	defer func() { stop("stopped") }()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-events:
			if !ok || e.Kind == "error" {
				stop("failed")
				retryAt = time.Now().Add(time.Duration(s.config.RetrySeconds) * time.Second)
				continue
			}
			if e.Kind == "status" && (e.Status == 1 || e.Status == 2 || e.Status == 5) {
				s.gate.Set(nil)
				s.set("authenticating")
				started = time.Now()
			}
			if e.Kind == "profile" && e.Profile != nil {
				endpoint, err := netip.ParseAddrPort(e.Profile.Endpoint)
				if err != nil || (s.BeforeEndpoint != nil && s.BeforeEndpoint(endpoint.Addr()) != nil) {
					stop("failed")
					retryAt = time.Now().Add(time.Duration(s.config.RetrySeconds) * time.Second)
					continue
				}
				t, err := vpn.New(*e.Profile, 1200)
				if err != nil {
					stop("failed")
					retryAt = time.Now().Add(time.Duration(s.config.RetrySeconds) * time.Second)
					continue
				}
				s.gate.Set(t)
				s.mu.Lock()
				s.last = time.Now()
				s.mu.Unlock()
				s.set("active")
			}
		case <-s.wake:
		case <-tick.C:
		}
		s.mu.Lock()
		state, last := s.state, s.last
		s.mu.Unlock()
		now := time.Now()
		if state == "active" && now.Sub(last) >= s.config.Idle() {
			stop("idle")
			continue
		}
		if state == "authenticating" && now.Sub(started) > time.Duration(s.config.AuthTimeoutSeconds)*time.Second {
			stop("failed")
			retryAt = now.Add(time.Duration(s.config.RetrySeconds) * time.Second)
			continue
		}
		if (state == "idle" || state == "failed") && !last.IsZero() && now.Sub(last) < s.config.Idle() && !now.Before(retryAt) {
			runctx, c := context.WithCancel(ctx)
			cancel = c
			started = now
			s.set("authenticating")
			if s.source != nil {
				events = s.source(runctx)
			} else {
				events = s.authenticate(runctx)
			}
		}
	}
}
func (s *Session) authenticate(ctx context.Context) <-chan auth.Event {
	out := make(chan auth.Event, 64)
	finishedWorker := make(chan struct{})
	s.workerDone = finishedWorker
	go func() {
		defer close(finishedWorker)
		defer close(out)
		emit := func(e auth.Event) bool {
			select {
			case out <- e:
				return true
			case <-ctx.Done():
				return false
			}
		}
		if s.config.ProfileFile != "" {
			b, e := os.ReadFile(s.config.ProfileFile)
			var p vpn.Profile
			if e == nil {
				e = json.Unmarshal(b, &p)
			}
			if e == nil {
				e = p.Validate()
			}
			if e != nil {
				emit(auth.Event{Kind: "error"})
				return
			}
			if !emit(auth.Event{Kind: "profile", Profile: &p}) {
				return
			}
			<-ctx.Done()
			return
		}
		args := append([]string{}, s.config.AuthCommand...)
		if len(args) == 0 {
			host, _, _ := net.SplitHostPort(s.config.AuthHost)
			lookupctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			// Bypass the domain DNS64 rule to avoid recursively authenticating
			// while resolving vpn-stu.ynu.ac.jp itself.
			bootstrap := &net.Resolver{PreferGo: true, Dial: func(c context.Context, n, a string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(c, n, s.config.PublicDNS)
			}}
			ips, e := bootstrap.LookupNetIP(lookupctx, "ip4", host)
			cancel()
			if e != nil || len(ips) == 0 {
				emit(auth.Event{Kind: "error"})
				return
			}
			endpoint := netip.AddrPortFrom(ips[0], 10000).String()
			if s.BeforeEndpoint != nil {
				if e = s.BeforeEndpoint(ips[0]); e != nil {
					log.Print("authentication endpoint bypass failed")
					emit(auth.Event{Kind: "error"})
					return
				}
			}
			if e = auth.RunClient(ctx, s.SIMPath, endpoint, emit); e != nil && ctx.Err() == nil {
				log.Printf("native authentication: %s", e)
				emit(auth.Event{Kind: "error"})
			}
			return
		}

		cmd := exec.Command(args[0], args[1:]...)
		stdout, e := cmd.StdoutPipe()
		if e != nil {
			emit(auth.Event{Kind: "error"})
			return
		}
		stdin, e := cmd.StdinPipe()
		if e != nil {
			emit(auth.Event{Kind: "error"})
			return
		}
		cmd.Stderr = io.Discard
		if e = cmd.Start(); e != nil {
			emit(auth.Event{Kind: "error"})
			return
		}
		finished := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				io.WriteString(stdin, "stop\n")
				stdin.Close()
				select {
				case <-finished:
				case <-time.After(2 * time.Second):
					cmd.Process.Kill()
				}
			case <-finished:
			}
		}()
		decoder := json.NewDecoder(stdout)
		for {
			var event auth.Event
			if e = decoder.Decode(&event); e != nil {
				break
			}
			if !emit(event) {
				break
			}
		}
		stdin.Close()
		cmd.Wait()
		close(finished)
		if ctx.Err() == nil {
			log.Print("authentication helper exited; session closed")
			emit(auth.Event{Kind: "error"})
		}
	}()
	return out
}
func (s *Session) CheckDependencies() error {
	if len(s.config.AuthCommand) > 0 {
		_, e := exec.LookPath(s.config.AuthCommand[0])
		return e
	}
	if s.config.ProfileFile != "" {
		_, e := os.Stat(s.config.ProfileFile)
		return e
	}
	b, e := auth.ReadSIMFile(s.SIMPath)
	if e != nil {
		return errors.New("authentication file missing; place .kkm under the current directory (depth <= 3) or use --auth PATH")
	}
	_, e = auth.ParseSIM(b)
	if e != nil {
		return e
	}
	return nil
}
