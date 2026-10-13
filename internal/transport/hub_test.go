package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/auth"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/devices"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/protocol"
)

type fakeAgent struct {
	ws *websocket.Conn
	id string
}

func newFakeAgent(t *testing.T, url, id string, pub ed25519.PublicKey, priv ed25519.PrivateKey) *fakeAgent {
	t.Helper()
	u := "ws" + strings.TrimPrefix(url, "http") + "/agent/ws"
	ws, _, e := websocket.DefaultDialer.Dial(u, nil)
	if e != nil {
		t.Fatal(e)
	}
	f := &fakeAgent{ws: ws, id: id}
	sendFake(t, ws, protocol.Envelope{Version: protocol.Version, Type: "hello", DeviceID: id})
	_, b, e := ws.ReadMessage()
	if e != nil {
		t.Fatal(e)
	}
	challenge, e := protocol.Decode(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Challenge string `json:"challenge"`
	}
	if e = json.Unmarshal(challenge.Arguments, &v); e != nil {
		t.Fatal(e)
	}
	nonce, e := auth.DecodeKey(v.Challenge, 32)
	if e != nil {
		t.Fatal(e)
	}
	sig := auth.SignChallenge(priv, id, nonce)
	sendFake(t, ws, protocol.Envelope{Version: protocol.Version, Type: "proof", DeviceID: id, Arguments: raw(map[string]string{"signature": auth.EncodeKey(sig)})})
	_, b, e = ws.ReadMessage()
	if e != nil {
		t.Fatal(e)
	}
	welcome, e := protocol.Decode(bytes.NewReader(b))
	if e != nil || welcome.Type != "welcome" {
		t.Fatalf("expected welcome; got %#v, %v", welcome, e)
	}
	return f
}
func sendFake(t *testing.T, ws *websocket.Conn, e protocol.Envelope) {
	t.Helper()
	b, err := protocol.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if err = ws.WriteMessage(websocket.TextMessage, b); err != nil {
		t.Fatal(err)
	}
}
func newTestHub(t *testing.T, deviceIDs ...string) (*Hub, *devices.Registry, *httptest.Server, map[string]*fakeAgent) {
	t.Helper()
	regs := make([]RegisteredDevice, 0, len(deviceIDs))
	keys := map[string]ed25519.PrivateKey{}
	for _, id := range deviceIDs {
		pub, priv, e := auth.GenerateDeviceKey()
		if e != nil {
			t.Fatal(e)
		}
		regs = append(regs, RegisteredDevice{ID: id, Name: id, PublicKey: pub})
		keys[id] = priv
	}
	r := devices.NewRegistry()
	h := NewHub(regs, r, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	srv := httptest.NewServer(h)
	agents := make(map[string]*fakeAgent)
	for _, id := range deviceIDs {
		agents[id] = newFakeAgent(t, srv.URL, id, regsByID(regs, id).PublicKey, keys[id])
	}
	return h, r, srv, agents
}
func regsByID(regs []RegisteredDevice, id string) RegisteredDevice {
	for _, r := range regs {
		if r.ID == id {
			return r
		}
	}
	return RegisteredDevice{}
}

func TestConcurrentRequestsAreCorrelatedOutOfOrderAndIsolated(t *testing.T) {
	h, _, srv, a := newTestHub(t, "one", "two")
	defer srv.Close()
	defer a["one"].ws.Close()
	defer a["two"].ws.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type result struct {
		device string
		method string
		value  string
		err    error
	}
	out := make(chan result, 3)
	for _, v := range []struct{ id, method string }{{"one", "alpha"}, {"one", "beta"}, {"two", "gamma"}} {
		v := v
		go func() {
			b, e := h.Do(ctx, v.id, v.method, map[string]string{"method": v.method})
			out <- result{device: v.id, method: v.method, value: string(b), err: e}
		}()
	}
	reqs := map[string][]protocol.Envelope{"one": {}, "two": {}}
	for id, f := range a {
		want := 2
		if id == "two" {
			want = 1
		}
		_ = f.ws.SetReadDeadline(time.Now().Add(2 * time.Second))
		for len(reqs[id]) < want {
			_, b, e := f.ws.ReadMessage()
			if e != nil {
				t.Fatal(e)
			}
			m, e := protocol.Decode(bytes.NewReader(b))
			if e != nil {
				t.Fatal(e)
			}
			if m.Type != "request" {
				continue
			}
			reqs[id] = append(reqs[id], m)
		}
	}
	// An unknown response is ignored, and the real replies deliberately arrive out of order.
	unknown := protocol.Envelope{Version: protocol.Version, Type: "response", RequestID: "unknown", DeviceID: "one", OK: true, Result: json.RawMessage(`{"method":"unknown"}`)}
	sendFake(t, a["one"].ws, unknown)
	for i := len(reqs["one"]) - 1; i >= 0; i-- {
		q := reqs["one"][i]
		arg := map[string]string{}
		_ = json.Unmarshal(q.Arguments, &arg)
		sendFake(t, a["one"].ws, protocol.Envelope{Version: protocol.Version, Type: "response", RequestID: q.RequestID, DeviceID: "one", OK: true, Result: json.RawMessage(`{"method":"` + arg["method"] + `"}`)})
	}
	q := reqs["two"][0]
	sendFake(t, a["two"].ws, protocol.Envelope{Version: protocol.Version, Type: "response", RequestID: q.RequestID, DeviceID: "two", OK: true, Result: json.RawMessage(`{"method":"gamma"}`)})
	for range 3 {
		r := <-out
		if r.err != nil {
			t.Fatal(r.err)
		}
		if !strings.Contains(r.value, r.method) {
			t.Fatalf("response crossed: requested %s got %s", r.method, r.value)
		}
	}
}

func TestReplacingDeviceConnectionAndReconnect(t *testing.T) {
	pub, priv, e := auth.GenerateDeviceKey()
	if e != nil {
		t.Fatal(e)
	}
	reg := RegisteredDevice{ID: "device", Name: "Device", PublicKey: pub}
	r := devices.NewRegistry()
	h := NewHub([]RegisteredDevice{reg}, r, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	srv := httptest.NewServer(h)
	defer srv.Close()
	old := newFakeAgent(t, srv.URL, reg.ID, reg.PublicKey, priv)
	replacement := newFakeAgent(t, srv.URL, reg.ID, reg.PublicKey, priv)
	defer replacement.ws.Close()
	if h.OnlineCount() != 1 {
		t.Fatalf("expected one live connection, got %d", h.OnlineCount())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, e := h.Do(ctx, reg.ID, "system.info", map[string]any{}); done <- e }()
	_ = replacement.ws.SetReadDeadline(time.Now().Add(time.Second))
	_, b, e := replacement.ws.ReadMessage()
	if e != nil {
		t.Fatal(e)
	}
	req, e := protocol.Decode(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	sendFake(t, replacement.ws, protocol.Envelope{Version: protocol.Version, Type: "response", RequestID: req.RequestID, DeviceID: reg.ID, OK: true, Result: json.RawMessage(`{"hostname":"new"}`)})
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	_ = old.ws.Close()
	replacement.ws.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if h.OnlineCount() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h.OnlineCount() != 0 {
		t.Fatal("device remained online after disconnect")
	}
	again := newFakeAgent(t, srv.URL, reg.ID, reg.PublicKey, priv)
	defer again.ws.Close()
	if h.OnlineCount() != 1 {
		t.Fatal("device did not reconnect")
	}
}
