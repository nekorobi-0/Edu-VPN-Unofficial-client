package auth

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/wmnsk/milenage"
	"net"
	"net/netip"
	"time"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/vpn"
)

// Client implements recovered LTE and 5G authentication without vendor code.
// Unsupported variants fail explicitly; no DLL fallback is used.
type Client struct {
	sim                                                                 SIM
	private                                                             []byte
	autn, random, res, kenb, nasEnc, nasInt, transportEnc, transportInt []byte
	ksi                                                                 byte
	challenged, secured, active                                         bool
	lastSQN                                                             uint32
	ckik, kamf                                                          []byte
	fiveG                                                               bool
	nasCipher                                                           byte
	nasDL, nasUL                                                        uint32
	nkEnc, nkInt                                                        []byte
	uplink                                                              uint32
}

func (c *Client) challenge(m message) (message, error) {
	if c.challenged {
		return message{}, errors.New("unexpected repeated authentication challenge")
	}
	fs, e := parseFields(m.payload)
	if e != nil {
		return message{}, e
	}
	for _, f := range fs {
		switch f.number {
		case 1:
			c.autn = f.data
		case 2:
			c.random = f.data
		case 3:
			c.ksi = byte(f.value)
		}
	}
	if len(c.autn) != 16 || len(c.random) != 16 {
		return message{}, errors.New("invalid authentication challenge")
	}
	mil := milenage.NewWithOPc(c.sim.K[:], c.sim.OPc[:], c.random, 1, binary.BigEndian.Uint16(c.autn[6:8]))
	res, ck, ik, ak, e := mil.F2345()
	if e != nil {
		return message{}, errors.New("SIM challenge calculation failed")
	}
	var sqn uint64
	for i := 0; i < 6; i++ {
		sqn = sqn<<8 | uint64(c.autn[i]^ak[i])
	}
	mil.SQN = binary.BigEndian.AppendUint64(nil, sqn)[2:]
	mac, e := mil.F1()
	if e != nil || !hmac.Equal(mac, c.autn[8:]) {
		return message{}, errors.New("SIM challenge authenticity check failed")
	}
	// MCC/MNC follow the native wrapper: IMSI[0:3], IMSI[3:5].
	d := func(i int) byte { return c.sim.IMSI[i] - '0' }
	plmn := []byte{d(1)<<4 | d(0), 0xf0 | d(2), d(4)<<4 | d(3)}
	kasme := derive(append(append([]byte(nil), ck...), ik...), 0x10, plmn, c.autn[:6])
	c.ckik = append(append([]byte(nil), ck...), ik...)
	c.kenb = derive(kasme, 0x11, []byte{0, 0, 0, 0})
	c.nasInt = derive(kasme, 0x15, []byte{2}, []byte{2})[16:]
	c.nasEnc = derive(kasme, 0x15, []byte{1}, []byte{2})[16:]
	c.res = append([]byte(nil), res...)
	c.challenged = true
	return message{id: 3, direction: 1, version: 2, sqn: m.sqn, payload: bytesField(nil, 1, res)}, nil
}

func (c *Client) securityMode(m message) ([]message, error) {
	if !c.challenged || c.secured {
		return nil, errors.New("unexpected security mode command")
	}
	p := m.payload
	if len(p) < 2 || int(p[1])+2 > len(p) {
		return nil, errors.New("invalid NAS security mode length")
	}
	nas := p[2 : 2+int(p[1])]
	if len(nas) < 9 || nas[0]>>4 != 3 || nas[0]&15 != 7 || nas[6] != 7 || nas[7] != 0x5d || nas[8] != 0x22 {
		return nil, errors.New("unsupported NAS security algorithms")
	}
	mac, e := integrity(c.nasInt, 0, 1, nas[5:])
	if e != nil || !hmac.Equal(mac, nas[1:5]) {
		return nil, errors.New("NAS security integrity check failed")
	}
	// NK keys are derived from the four-byte security-command MAC.
	// The subsequent security-context exchange replaces transport keys.
	m.direction = 1
	identity := message{id: 26, direction: 1, version: 2, payload: bytesField(nil, 1, []byte("0101010101010101"))}
	return []message{m, identity}, nil
}
func (c *Client) contextBody(m message) []byte {
	b := append([]byte(nil), []byte(c.sim.IMSI)...)
	b = append(b, c.random...)
	b = append(b, c.autn...)
	b = append(b, c.ksi)
	b = append(b, c.res...)
	return append(b, m.canonical()...)
}
func (c *Client) securityContext(m message) (message, error) {
	if c.fiveG {
		return c.securityContext5G(m)
	}
	if !c.challenged || c.secured || len(m.nonce) == 0 || m.flags&3 != 3 || m.flags & ^uint32(7) != 0 {
		return message{}, errors.New("unexpected security context")
	}
	enc := derive(c.kenb, 8, m.nonce)
	ik := derive(c.kenb, 9, m.nonce)
	if e := verifyMessageMAC(m, ik, c.contextBody(m)); e != nil {
		return message{}, e
	}
	plain, e := crypt(enc, m.sqn, 1, m.payload)
	if e != nil {
		return message{}, e
	}
	fs, e := parseFields(plain)
	if e != nil {
		return message{}, e
	}
	// The native client replaces the server's NAS key fields with locally
	// derived keys and sets both algorithms to AES before acknowledging.
	var nasPayload []byte
	for _, f := range fs {
		if f.number == 5 {
			nasPayload = f.data
		}
	}
	plain = bytesField(nil, 1, c.nasEnc)
	plain = bytesField(plain, 2, c.nasInt)
	plain = intField(plain, 3, 2)
	plain = intField(plain, 4, 2)
	plain = bytesField(plain, 5, nasPayload)
	c.transportEnc = enc
	c.transportInt = ik
	c.secured = true
	c.lastSQN = m.sqn
	m.direction = 1
	// Native implementation encrypts and signs this acknowledgement with direction=1.
	m.payload, e = crypt(enc, m.sqn, 1, plain)
	if e != nil {
		return message{}, e
	}
	m.mac, e = messageMAC(m, ik, 1, c.contextBody(m))
	return m, e
}
func (c *Client) success(m message, authEndpoint string) (vpn.Profile, error) {
	var p vpn.Profile
	if !c.secured || c.active || m.sqn <= c.lastSQN {
		return p, errors.New("unexpected authentication success")
	}
	var plain []byte
	var e error
	if c.fiveG {
		if m.flags != 3 {
			return p, errors.New("invalid 5G success protection")
		}
		plain, e = c.read5G(m)
	} else {
		if m.flags&3 != 3 || m.flags & ^uint32(7) != 0 {
			return p, errors.New("invalid success protection")
		}
		if e = verifyMessageMAC(m, c.transportInt, m.canonical()); e != nil {
			return p, e
		}
		plain, e = crypt(c.transportEnc, m.sqn, 1, m.payload)
	}
	if e != nil {
		return p, e
	}

	fs, e := parseFields(plain)
	if e != nil {
		return p, e
	}
	var peer []byte
	var endpoint string
	for _, f := range fs {
		switch f.number {
		case 3:
			p.Address = string(f.data)
		case 7:
			peer = f.data
		case 8:
			endpoint = string(f.data)
		}
	}
	remote, e := netip.ParseAddrPort(endpoint)
	if e != nil || remote.Port() == 0 {
		return p, errors.New("invalid assigned WireGuard endpoint")
	}
	authAddr, e := netip.ParseAddrPort(authEndpoint)
	if e != nil {
		return p, errors.New("invalid authentication endpoint")
	}
	if len(peer) != 32 {
		return p, errors.New("invalid assigned WireGuard public key")
	}
	b64 := base64.StdEncoding.EncodeToString
	p.PrivateKey = b64(c.private)
	p.PublicKey = b64(peer)
	p.PresharedKey = b64(derive(c.kenb, 7, []byte("WLAN-gen")))
	p.Endpoint = netip.AddrPortFrom(authAddr.Addr(), remote.Port()).String()
	if e = p.Validate(); e != nil {
		return vpn.Profile{}, e
	}
	c.active = true
	c.lastSQN = m.sqn
	return p, nil
}

// RunClient keeps the authentication TCP connection open for the WG session.
// It sends only redacted errors and profile events to its owner.
func RunClient(ctx context.Context, simPath, endpoint string, emit func(Event) bool) error {
	raw, e := ReadSIMFile(simPath)
	if e != nil {
		return errors.New("cannot read authentication file")
	}
	sim, e := ParseSIM(raw)
	if e != nil {
		return e
	}
	priv, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return errors.New("WireGuard key generation failed")
	}
	c := Client{sim: sim, private: priv.Bytes()}
	conn, e := (&net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", endpoint)
	if e != nil {
		return errors.New("authentication TCP connection failed")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	defer func() {
		if c.active {
			conn.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
			_ = writeMessage(conn, message{id: 20, direction: 1, version: 2, sqn: c.nasUL})
		}
	}()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	payload := bytesField(nil, 1, []byte(sim.IMSI))
	payload = bytesField(payload, 2, []byte("lte-x.co.jp"))
	payload = bytesField(payload, 3, []byte("Tracking Area"))
	payload = bytesField(payload, 4, []byte("1234"))
	payload = bytesField(payload, 5, []byte("127.0.0.1"))
	payload = intField(payload, 7, 4)
	payload = bytesField(payload, 8, priv.PublicKey().Bytes())
	if e = writeMessage(conn, message{id: 1, direction: 1, version: 2, payload: payload}); e != nil {
		return errors.New("authentication connect send failed")
	}
	for {
		m, e := readMessage(conn)
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("authentication receive: %w", e)
		}
		var replies []message
		switch m.id {
		case 64:
			r, err := c.challenge5G(m)
			e = err
			replies = []message{r}
		case 2:
			r, err := c.challenge(m)
			e = err
			replies = []message{r}
		case 65, 66:
			r, err := c.relayNAS5G(m)
			e = err
			replies = []message{r}
		case 4:
			replies, e = c.securityMode(m)
		case 25:
			r, err := c.securityContext(m)
			e = err
			replies = []message{r}
		case 6:
			var p vpn.Profile
			p, e = c.success(m, endpoint)
			if e == nil {
				if !emit(Event{Kind: "profile", Profile: &p}) {
					return ctx.Err()
				}
				conn.SetDeadline(time.Time{})
			}
		case 18: // Authenticated echoes are never accepted unsigned.
			if !c.active || m.sqn <= c.lastSQN {
				return errors.New("unexpected authentication echo")
			}
			if c.fiveG {
				var plain []byte
				plain, e = c.read5G(m)
				if e == nil {
					var reply message
					reply, e = c.send5G(19, plain, m.flags&4 != 0)
					replies = []message{reply}
					c.lastSQN = m.sqn
				}
				break
			}
			e = verifyMessageMAC(m, c.transportInt, m.canonical())
			if e == nil {
				c.lastSQN = m.sqn
				m.id = 19
				m.direction = 1
				m.mac, e = messageMAC(m, c.transportInt, 0, m.canonical())
				replies = []message{m}
			}
		case 7, 13, 16, 21, 22, 27:
			return fmt.Errorf("authentication server ended session (message %d)", m.id)
		default:
			return fmt.Errorf("unsupported authentication message %d; native protocol port is incomplete", m.id)
		}
		if e != nil {
			return e
		}
		for _, r := range replies {
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if e = writeMessage(conn, r); e != nil {
				return errors.New("authentication reply send failed")
			}
			conn.SetWriteDeadline(time.Time{})
		}
	}
}
