package auth

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChallengeProof(t *testing.T) {
	pub, priv, err := GenerateDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	sig := SignChallenge(priv, "device", nonce)
	if !VerifyChallenge(pub, "device", nonce, sig) {
		t.Fatal("valid proof rejected")
	}
	if VerifyChallenge(pub, "other", nonce, sig) {
		t.Fatal("proof accepted for another device")
	}
	if VerifyChallenge(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), "device", nonce, sig) {
		t.Fatal("proof accepted with another key")
	}
}
func TestBearerMiddleware(t *testing.T) {
	token := "0123456789abcdef0123456789abcdef"
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h, err := BearerMiddleware(token, next)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		auth string
		want int
	}{{"Bearer " + token, 204}, {"Bearer wrong", 401}, {"", 401}} {
		r := httptest.NewRequest("POST", "/mcp", nil)
		if tc.auth != "" {
			r.Header.Set("Authorization", tc.auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("got %d want %d", w.Code, tc.want)
		}
	}
}
