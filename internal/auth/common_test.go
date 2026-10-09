package auth

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSIMValidationNeverIncludesKeys(t *testing.T) {
	secret := strings.Repeat("ab", 16)
	b := base64.StdEncoding.EncodeToString([]byte("imsi-123456789012345," + secret + "," + strings.Repeat("cd", 16)))
	if _, e := ParseSIM([]byte(b)); e != nil {
		t.Fatal(e)
	}
	bad := base64.StdEncoding.EncodeToString([]byte("imsi-123456789012345," + secret + ",BAD"))
	if _, e := ParseSIM([]byte(bad)); e == nil || strings.Contains(e.Error(), secret) {
		t.Fatal("bad key accepted or disclosed")
	}
}
