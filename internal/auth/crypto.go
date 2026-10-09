package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// The vendor KDF uses FC || parameter || uint16BE(parameter length), HMAC-SHA256.
func derive(key []byte, fc byte, params ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte{fc})
	for _, p := range params {
		h.Write(p)
		h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(p))))
	}
	return h.Sum(nil)
}
func cmac(key, data []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, errors.New("invalid authentication encryption key")
	}
	var zero, l [16]byte
	block.Encrypt(l[:], zero[:])
	double := func(a [16]byte) (b [16]byte) {
		for i := 0; i < 15; i++ {
			b[i] = a[i]<<1 | a[i+1]>>7
		}
		b[15] = a[15] << 1
		if a[0]&128 != 0 {
			b[15] ^= 0x87
		}
		return
	}
	k1 := double(l)
	k2 := double(k1)
	n := (len(data) + 15) / 16
	if n == 0 {
		n = 1
	}
	var x, last [16]byte
	for i := 0; i < n-1; i++ {
		for j := range x {
			x[j] ^= data[i*16+j]
		}
		block.Encrypt(x[:], x[:])
	}
	remain := data[(n-1)*16:]
	copy(last[:], remain)
	k := k1
	if len(remain) != 16 {
		last[len(remain)] = 128
		k = k2
	}
	for j := range last {
		last[j] ^= k[j] ^ x[j]
	}
	block.Encrypt(last[:], last[:])
	return append([]byte(nil), last[:]...), nil
}
func integrity(key []byte, count uint32, direction byte, data []byte) ([]byte, error) {
	return integrityBearer(key, count, 0, direction, data)
}
func integrityBearer(key []byte, count uint32, bearer, direction byte, data []byte) ([]byte, error) {
	b := make([]byte, 8, len(data)+8)
	binary.BigEndian.PutUint32(b, count)
	b[4] = (bearer&31)<<3 | direction<<2
	b = append(b, data...)
	mac, e := cmac(key, b)
	if e != nil {
		return nil, e
	}
	return mac[:4], nil
}
func crypt(key []byte, count uint32, direction byte, data []byte) ([]byte, error) {
	return cryptBearer(key, count, 0, direction, data)
}
func cryptBearer(key []byte, count uint32, bearer, direction byte, data []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, errors.New("invalid authentication encryption key")
	}
	var iv [16]byte
	binary.BigEndian.PutUint32(iv[:], count)
	iv[4] = (bearer&31)<<3 | direction<<2
	out := make([]byte, len(data))
	cipher.NewCTR(b, iv[:]).XORKeyStream(out, data)
	return out, nil
}
func messageMAC(m message, key []byte, direction byte, body []byte) ([]byte, error) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, m.sqn)
	b[4] = direction << 2
	b = append(b, byte(m.sqn))
	b = append(b, body...)
	return cmac(key, b)
}
func verifyMessageMAC(m message, key []byte, body []byte) error {
	mac, e := messageMAC(m, key, 1, body)
	if e != nil {
		return e
	}
	if len(m.mac) != 16 || !hmac.Equal(mac, m.mac) {
		return errors.New("authentication message integrity check failed")
	}
	return nil
}
