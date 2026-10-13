// Package auth implements device proof-of-possession and MCP bearer verification.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func GenerateDeviceKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func NewChallenge() ([]byte, error) { b := make([]byte, 32); _, err := rand.Read(b); return b, err }

func SignChallenge(priv ed25519.PrivateKey, deviceID string, challenge []byte) []byte {
	msg := append([]byte("ato-relay-device-v1\x00"+deviceID+"\x00"), challenge...)
	return ed25519.Sign(priv, msg)
}

func VerifyChallenge(pub ed25519.PublicKey, deviceID string, challenge, signature []byte) bool {
	msg := append([]byte("ato-relay-device-v1\x00"+deviceID+"\x00"), challenge...)
	return ed25519.Verify(pub, msg, signature)
}

func EncodeKey(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
func DecodeKey(s string, size int) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil || len(b) != size {
		return nil, errors.New("invalid key encoding or size")
	}
	return b, nil
}

func BearerMiddleware(token string, next http.Handler) (http.Handler, error) {
	if len(token) < 32 {
		return nil, errors.New("MCP bearer token must contain at least 32 characters")
	}
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			unauthorized(w)
			return
		}
		got := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
		if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
			unauthorized(w)
			return
		}
		next.ServeHTTP(w, r)
	}), nil
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="ATO Computer Relay"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func ValidateMCPToken(token string) error {
	if len(token) < 32 {
		return fmt.Errorf("bearer token is too short")
	}
	return nil
}

func ChallengeExpiry() time.Duration { return 30 * time.Second }
