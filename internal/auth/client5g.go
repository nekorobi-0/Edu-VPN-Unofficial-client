package auth

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
)

func (c *Client) challenge5G(m message) (message, error) {
	fs, e := parseFields(m.payload)
	if e != nil {
		return message{}, e
	}
	var packed uint32
	for _, f := range fs {
		if f.number == 3 {
			packed = uint32(f.value)
		}
	}
	p := bytesField(nil, 1, nil)
	for _, f := range fs {
		if f.number == 1 || f.number == 2 {
			p = bytesField(p, f.number, f.data)
		}
	}
	p = intField(p, 3, packed>>16)
	copyMsg := m
	copyMsg.payload = p
	r, e := c.challenge(copyMsg)
	if e != nil {
		return message{}, e
	}
	mnc := c.sim.IMSI[3:6]
	if c.sim.IMSI[:3] == "440" || c.sim.IMSI[:3] == "441" || c.sim.IMSI[:5] == "00101" {
		mnc = "0" + c.sim.IMSI[3:5]
	}
	snn := []byte(fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", mnc, c.sim.IMSI[:3]))
	// 5G-AKA uses the same Milenage outputs; RES* is the lower 128 bits.
	resStar := derive(c.ckik, 0x6b, snn, c.random, c.res)[16:]
	kausf := derive(c.ckik, 0x6a, snn, c.autn[:6])
	kseaf := derive(kausf, 0x6c, snn)
	abba := binary.BigEndian.AppendUint16(nil, uint16(packed))
	c.kamf = derive(kseaf, 0x6d, []byte(c.sim.IMSI), abba)
	c.kenb = derive(c.kamf, 0x6e, []byte{0, 0, 0, 0}, []byte{1})
	c.fiveG = true
	c.res = resStar
	r.payload = bytesField(nil, 1, resStar)
	if len(c.kamf) != 32 {
		return message{}, errors.New("5G key derivation failed")
	}
	return r, nil
}

func (c *Client) securityContext5G(m message) (message, error) {
	if !c.challenged || c.secured || len(m.nonce) == 0 || m.flags != 5 {
		return message{}, errors.New("unexpected 5G security context")
	}
	fs, err := parseFields(m.payload)
	if err != nil {
		return message{}, err
	}
	var cipherAlg, integrityAlg uint64
	var payload []byte
	for _, f := range fs {
		switch f.number {
		case 3:
			cipherAlg = f.value
		case 4:
			integrityAlg = f.value
		case 5:
			payload = f.data
		}
	}
	if (cipherAlg != 0 && cipherAlg != 2) || integrityAlg != 2 {
		return message{}, fmt.Errorf("unsupported 5G security algorithms (%d/%d)", cipherAlg, integrityAlg)
	}
	c.nasCipher = byte(cipherAlg)
	c.nasEnc = derive(c.kamf, 0x69, []byte{1}, []byte{byte(cipherAlg)})[16:]
	c.nasInt = derive(c.kamf, 0x69, []byte{2}, []byte{2})[16:]
	c.transportEnc = derive(c.kenb, 8, m.nonce)
	c.transportInt = derive(c.kenb, 9, m.nonce)
	mac, err := integrityBearer(c.nasInt, 0, 1, 1, append([]byte{0}, payload...))
	if err != nil {
		return message{}, err
	}
	c.nkEnc = derive(mac, 1, []byte("NKenc-gen"))
	c.nkInt = derive(mac, 2, []byte("NKint-gen"))
	if err = verifyMessageMAC(m, c.nkInt, m.canonical()); err != nil {
		return message{}, err
	}
	p := intField(nil, 3, uint32(cipherAlg))
	p = intField(p, 4, 2)
	p = bytesField(p, 5, []byte("0101010101010101"))
	r, err := c.send5G(25, p, true)
	if err != nil {
		return message{}, err
	}
	c.secured = true
	c.lastSQN = m.sqn
	return r, nil
}
func (c *Client) send5G(id uint32, payload []byte, nk bool) (message, error) {
	m := message{id: id, direction: 1, version: 2, flags: 3, sqn: c.uplink}
	enc, ik := c.transportEnc, c.transportInt
	if nk {
		m.flags |= 4
		enc, ik = c.nkEnc, c.nkInt
	}
	var err error
	m.payload, err = crypt(enc, m.sqn, 0, payload)
	if err != nil {
		return message{}, err
	}
	m.mac, err = messageMAC(m, ik, 0, m.canonical())
	if err == nil {
		c.uplink++
	}
	return m, err
}
func (c *Client) read5G(m message) ([]byte, error) {
	if m.flags&1 == 0 || m.flags & ^uint32(7) != 0 {
		return nil, errors.New("invalid 5G message protection")
	}
	enc, ik := c.transportEnc, c.transportInt
	if m.flags&4 != 0 {
		enc, ik = c.nkEnc, c.nkInt
	}
	if err := verifyMessageMAC(m, ik, m.canonical()); err != nil {
		return nil, err
	}
	if m.flags&2 != 0 {
		return crypt(enc, m.sqn, 1, m.payload)
	}
	return m.payload, nil
}

func (c *Client) relayNAS5G(m message) (message, error) {
	if !c.fiveG || !c.secured || m.sqn <= c.lastSQN || (m.flags != 3 && m.flags != 7) {
		return message{}, errors.New("unexpected 5G NAS relay")
	}
	plain, err := c.read5G(m)
	if err != nil {
		return message{}, err
	}
	fs, err := parseFields(plain)
	if err != nil {
		return message{}, err
	}
	var ptype, seq uint32
	var payload, mac []byte
	for _, f := range fs {
		switch f.number {
		case 1:
			ptype = uint32(f.value)
		case 3:
			seq = uint32(f.value)
		case 4:
			mac = f.data
		case 5:
			payload = f.data
		}
	}
	if ptype > 4 || seq > 255 {
		return message{}, errors.New("invalid 5G NAS metadata")
	}
	var response []byte
	if m.id == 66 {
		if ptype != 0 {
			expected, e := integrityBearer(c.nasInt, c.nasDL, 1, 1, append([]byte{byte(seq)}, payload...))
			if e != nil || !hmac.Equal(expected, mac) {
				return message{}, errors.New("5G NAS integrity check failed")
			}
		}
		if (ptype == 2 || ptype == 4) && c.nasCipher == 2 {
			payload, err = cryptBearer(c.nasEnc, c.nasDL, 1, 1, payload)
			if err != nil {
				return message{}, err
			}
		}
		c.nasDL++
		response = bytesField(nil, 5, payload)
	} else {
		if (ptype == 2 || ptype == 4) && c.nasCipher == 2 {
			payload, err = cryptBearer(c.nasEnc, c.nasUL, 1, 0, payload)
			if err != nil {
				return message{}, err
			}
		}
		if ptype != 0 {
			mac, err = integrityBearer(c.nasInt, c.nasUL, 1, 0, append([]byte{byte(c.nasUL)}, payload...))
			if err != nil {
				return message{}, err
			}
			response = bytesField(nil, 4, mac)
		}
		response = intField(response, 3, uint32(byte(c.nasUL)))
		response = bytesField(response, 5, payload)
		c.nasUL++
	}
	r, err := c.send5G(m.id, response, m.flags&4 != 0)
	if err == nil {
		c.lastSQN = m.sqn
	}
	return r, err
}
