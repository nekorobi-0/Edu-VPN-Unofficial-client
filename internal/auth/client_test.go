package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"github.com/wmnsk/milenage"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func unhex(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func TestCMACKnownVectors(t *testing.T) {
	// NIST SP 800-38B / RFC 4493 AES-CMAC examples, including empty input.
	key := unhex("2b7e151628aed2a6abf7158809cf4f3c")
	input := unhex("6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51" + "30c81c46a35ce411")
	for _, tc := range []struct {
		n   int
		mac string
	}{{0, "bb1d6929e95937287fa37d129b756746"}, {16, "070a16b46b4d4144f79bdd9dd04a287c"}, {40, "dfa66747de9ae63030ca32611497c827"}} {
		got, e := cmac(key, input[:tc.n])
		if e != nil || !bytes.Equal(got, unhex(tc.mac)) {
			t.Fatalf("CMAC vector %d failed", tc.n)
		}
	}
}

type oneByteReader struct{ io.Reader }

func (r oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}
func TestTCPFramingFragmentationAndCoalescing(t *testing.T) {
	var b bytes.Buffer
	for _, id := range []uint32{2, 25, 6} {
		if e := writeMessage(&b, message{id: id, direction: 2, version: 2, payload: []byte{1, 2, 3}, sqn: id}); e != nil {
			t.Fatal(e)
		}
	}
	r := oneByteReader{&b}
	for _, id := range []uint32{2, 25, 6} {
		m, e := readMessage(r)
		if e != nil || m.id != id || m.sqn != id {
			t.Fatal("fragmented frame lost")
		}
	}
	_, e := readMessage(bytes.NewReader(binary.BigEndian.AppendUint32(nil, maxAuthFrame+1)))
	if e == nil {
		t.Fatal("unbounded frame accepted")
	}
}
func testSIM() SIM {
	var s SIM
	s.IMSI = "800010000000001" // synthetic; never the workspace SIM
	copy(s.K[:], unhex("465b5ce8b199b49faa5f0a2ee238a6bc"))
	copy(s.OPc[:], unhex("cd63cb71954a9f4e48a5994e37a02baf"))
	return s
}
func makeChallenge(t *testing.T, s SIM) message {
	t.Helper()
	mil := milenage.NewWithOPc(s.K[:], s.OPc[:], unhex("23553cbe9637a89d218ae64dae47bf35"), 0xff9bb4d0b607, 0xb9b9)
	if e := mil.ComputeAll(); e != nil {
		t.Fatal(e)
	}
	autn, e := mil.GenerateAUTN()
	if e != nil {
		t.Fatal(e)
	}
	p := bytesField(nil, 1, autn)
	p = bytesField(p, 2, mil.RAND)
	p = intField(p, 3, 1)
	return message{id: 2, direction: 2, version: 2, sqn: 1, payload: p}
}
func TestChallengeRejectsWrongSIMAndForgery(t *testing.T) {
	s := testSIM()
	m := makeChallenge(t, s)
	c := Client{sim: s}
	r, e := c.challenge(m)
	if e != nil {
		t.Fatal(e)
	}
	fs, _ := parseFields(r.payload)
	if !bytes.Equal(fs[0].data, unhex("a54211d5e3ba50bf")) {
		t.Fatal("Milenage RES differs from test set 1")
	}
	m.payload[len(m.payload)-5] ^= 1
	c = Client{sim: s}
	if _, e = c.challenge(m); e == nil {
		t.Fatal("modified challenge accepted")
	}
	c = Client{sim: s}
	c.sim.K[0] ^= 1
	if _, e = c.challenge(makeChallenge(t, s)); e == nil {
		t.Fatal("wrong SIM accepted")
	}
}
func TestGoAuthenticationLoopbackAndCancellation(t *testing.T) {
	s := testSIM()
	path := filepath.Join(t.TempDir(), "test.kkm")
	raw := base64.StdEncoding.EncodeToString([]byte("imsi-" + s.IMSI + "," + hex.EncodeToString(s.K[:]) + "," + hex.EncodeToString(s.OPc[:])))
	if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	challenge := makeChallenge(t, s)
	serverDone := make(chan error, 1)
	go func() {
		conn, e := ln.Accept()
		if e != nil {
			serverDone <- e
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		read := func() (message, error) {
			var h [4]byte
			if _, e := io.ReadFull(conn, h[:]); e != nil {
				return message{}, e
			}
			b := make([]byte, binary.BigEndian.Uint32(h[:]))
			if _, e := io.ReadFull(conn, b); e != nil {
				return message{}, e
			}
			fs, e := parseFields(b)
			m := message{}
			for _, f := range fs {
				switch f.number {
				case 1:
					m.id = uint32(f.value)
				case 2:
					m.direction = uint32(f.value)
				case 3:
					m.payload = f.data
				}
			}
			return m, e
		}
		m, e := read()
		if e != nil || m.id != 1 || m.direction != 1 {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		fs, e := parseFields(m.payload)
		pubLength := 0
		for _, f := range fs {
			if f.number == 8 {
				pubLength = len(f.data)
			}
		}
		if e != nil || pubLength != 32 {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		local := Client{sim: s}
		_, e = local.challenge(challenge)
		if e != nil {
			serverDone <- e
			return
		}
		if e = writeMessage(conn, challenge); e != nil {
			serverDone <- e
			return
		}
		if m, e = read(); e != nil || m.id != 3 {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		// The loopback transcript covers the recovered challenge/context/success
		// path. It is not evidence of university server compatibility.
		nonce := []byte("synthetic nonce")
		enc := derive(local.kenb, 8, nonce)
		ik := derive(local.kenb, 9, nonce)
		ctxMsg := message{id: 25, direction: 2, version: 2, flags: 7, sqn: 2, nonce: nonce}
		ctxMsg.payload, _ = crypt(enc, ctxMsg.sqn, 1, []byte{})
		ctxMsg.mac, _ = messageMAC(ctxMsg, ik, 1, local.contextBody(ctxMsg))
		if e = writeMessage(conn, ctxMsg); e != nil {
			serverDone <- e
			return
		}
		if m, e = read(); e != nil || m.id != 25 {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		p := bytesField(nil, 3, []byte("10.0.0.2"))
		p = bytesField(p, 7, bytes.Repeat([]byte{7}, 32))
		p = bytesField(p, 8, []byte("192.0.2.1:51820"))
		success := message{id: 6, direction: 2, version: 2, flags: 7, sqn: 3}
		success.payload, _ = crypt(enc, 3, 1, p)
		success.mac, _ = messageMAC(success, ik, 1, success.canonical())
		if e = writeMessage(conn, success); e != nil {
			serverDone <- e
			return
		}
		m, e = read()
		if e == nil && m.id != 20 {
			e = io.ErrUnexpectedEOF
		}
		serverDone <- e
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	profiles := make(chan Event, 1)
	go func() {
		done <- RunClient(ctx, path, ln.Addr().String(), func(e Event) bool { profiles <- e; return true })
	}()
	select {
	case e := <-profiles:
		if e.Profile == nil || e.Profile.Address != "10.0.0.2" || e.Profile.Endpoint != "127.0.0.1:51820" {
			t.Fatal("profile extraction failed")
		}
	case e := <-done:
		t.Fatalf("authentication exited early: %v", e)
	case <-time.After(3 * time.Second):
		t.Fatal("authentication timed out")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not stop TCP authentication")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("server did not see connection close")
	}
}
func TestSuccessFailsClosedWithoutValidIntegrity(t *testing.T) {
	c := Client{secured: true, lastSQN: 1, transportInt: make([]byte, 32)}
	if _, e := c.success(message{id: 6, direction: 2, version: 2, flags: 7, sqn: 2, payload: []byte{1}}, "127.0.0.1:10000"); e == nil {
		t.Fatal("unsigned success accepted")
	}
}

func TestOuterMACIsFullCMACAndRejectsTruncation(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	m := message{id: 66, direction: 2, version: 2, flags: 3, sqn: 1, payload: []byte{1, 2, 3}}
	m.mac, _ = messageMAC(m, key, 1, m.canonical())
	if len(m.mac) != 16 || verifyMessageMAC(m, key, m.canonical()) != nil {
		t.Fatal("outer authentication MAC must contain all 16 CMAC bytes")
	}
	m.mac = m.mac[:4]
	if verifyMessageMAC(m, key, m.canonical()) == nil {
		t.Fatal("truncated MAC accepted")
	}
}
func Test5GContextAndNASIntegrity(t *testing.T) {
	s := testSIM()
	challenge := makeChallenge(t, s)
	challenge.id = 64
	c := Client{sim: s}
	if _, err := c.challenge5G(challenge); err != nil {
		t.Fatal(err)
	}
	contextPayload := intField(nil, 4, 2)
	nasPayload := []byte{0x7e, 0, 0x5d}
	contextPayload = bytesField(contextPayload, 5, nasPayload)
	nasInt := derive(c.kamf, 0x69, []byte{2}, []byte{2})[16:]
	mac, _ := integrityBearer(nasInt, 0, 1, 1, append([]byte{0}, nasPayload...))
	nkInt := derive(mac, 2, []byte("NKint-gen"))
	m := message{id: 25, direction: 2, version: 2, flags: 5, sqn: 0, nonce: []byte("synthetic 5G nonce"), payload: contextPayload}
	m.mac, _ = messageMAC(m, nkInt, 1, m.canonical())
	corrupted := m
	corrupted.mac = append([]byte(nil), m.mac...)
	corrupted.mac[15] ^= 1
	copyClient := c
	if _, err := copyClient.securityContext5G(corrupted); err == nil {
		t.Fatal("forged security context accepted")
	}
	ack, err := c.securityContext5G(m)
	if err != nil {
		t.Fatal(err)
	}
	if ack.flags != 7 || ack.sqn != 0 || len(ack.mac) != 16 || !c.secured {
		t.Fatal("5G context acknowledgement invalid")
	}
	payload := []byte{0x7e, 0, 0x42}
	nasMAC, _ := integrityBearer(c.nasInt, 0, 1, 1, append([]byte{0}, payload...))
	inner := intField(nil, 1, 1)
	inner = bytesField(inner, 4, nasMAC)
	inner = bytesField(inner, 5, payload)
	relay := message{id: 66, direction: 2, version: 2, flags: 3, sqn: 1}
	relay.payload, _ = crypt(c.transportEnc, 1, 1, inner)
	relay.mac, _ = messageMAC(relay, c.transportInt, 1, relay.canonical())
	bad := relay
	bad.payload = append([]byte(nil), relay.payload...)
	bad.payload[0] ^= 1
	if _, err = c.relayNAS5G(bad); err == nil {
		t.Fatal("forged NAS relay accepted")
	}
	response, err := c.relayNAS5G(relay)
	if err != nil {
		t.Fatal(err)
	}
	if response.id != 66 || c.nasDL != 1 || c.uplink != 2 {
		t.Fatal("5G NAS counters invalid")
	}
	if _, err = c.relayNAS5G(relay); err == nil {
		t.Fatal("replayed NAS relay accepted")
	}
	// A valid outer MAC must not conceal a forged inner NAS MAC.
	relay.sqn = 2
	inner[len(inner)-1] ^= 1
	relay.payload, _ = crypt(c.transportEnc, 2, 1, inner)
	relay.mac, _ = messageMAC(relay, c.transportInt, 1, relay.canonical())
	if _, err = c.relayNAS5G(relay); err == nil {
		t.Fatal("forged inner NAS accepted")
	}
}
