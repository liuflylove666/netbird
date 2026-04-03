package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	SecretLength = 20
	CodeDigits   = 6
	TimeStep     = 30
	WindowSize   = 1 // allow +/- 1 time step for clock skew
)

func GenerateSecret() (string, error) {
	secret := make([]byte, SecretLength)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func GenerateCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("invalid secret: %w", err)
	}

	counter := uint64(math.Floor(float64(t.Unix()) / float64(TimeStep)))

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0F
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7FFFFFFF

	code := value % uint32(math.Pow10(CodeDigits))
	return fmt.Sprintf("%0*d", CodeDigits, code), nil
}

func ValidateCode(secret string, code string) bool {
	now := time.Now()
	for i := -WindowSize; i <= WindowSize; i++ {
		t := now.Add(time.Duration(i*TimeStep) * time.Second)
		expected, err := GenerateCode(secret, t)
		if err != nil {
			continue
		}
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

// BuildOTPAuthURL builds the otpauth:// URI for QR code generation.
func BuildOTPAuthURL(secret, email, issuer string) string {
	u := url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   fmt.Sprintf("/%s:%s", issuer, email),
	}
	q := u.Query()
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", CodeDigits))
	q.Set("period", fmt.Sprintf("%d", TimeStep))
	u.RawQuery = q.Encode()
	return u.String()
}
