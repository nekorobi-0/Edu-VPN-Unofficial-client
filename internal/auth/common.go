package auth

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"github.com/nekorobi-0/YNU-VPN-Unofficial-client/internal/vpn"
)

type SIM struct {
	IMSI   string
	K, OPc [16]byte
}

func ParseSIM(raw []byte) (SIM, error) {
	var s SIM
	b, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if e != nil {
		return s, errors.New("invalid .kkm encoding")
	}
	fields := strings.Split(strings.TrimRight(string(b), "\r\n"), ",")
	if len(fields) != 3 {
		return s, errors.New("invalid .kkm structure")
	}
	s.IMSI = strings.TrimPrefix(fields[0], "imsi-")
	if !regexp.MustCompile(`^[0-9]{15}$`).MatchString(s.IMSI) {
		return SIM{}, errors.New("invalid IMSI format")
	}
	for i, v := range fields[1:] {
		b, e = hex.DecodeString(v)
		if e != nil || len(b) != 16 {
			return SIM{}, errors.New("invalid SIM key format")
		}
		if i == 0 {
			copy(s.K[:], b)
		} else {
			copy(s.OPc[:], b)
		}
	}
	return s, nil
}

type Event struct {
	Kind    string       `json:"kind"`
	Status  int          `json:"status,omitempty"`
	Profile *vpn.Profile `json:"profile,omitempty"`
	Error   string       `json:"error,omitempty"`
}
