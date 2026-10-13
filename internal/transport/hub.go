// Package transport implements the authenticated, outbound-agent WebSocket protocol.
package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/auth"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/devices"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/protocol"
)

const maxPendingPerDevice = 64
const maxPendingGlobally = 256

type RegisteredDevice struct {
	ID, Name  string
	PublicKey ed25519.PublicKey
}
type pendingResult struct {
	response protocol.Envelope
	err      error
}
type connection struct {
	id      string
	ws      *websocket.Conn
	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[string]chan pendingResult
	done    chan struct{}
	once    sync.Once
}

func (c *connection) close() { c.once.Do(func() { close(c.done); _ = c.ws.Close() }) }
func (c *connection) write(e protocol.Envelope) error {
	b, err := protocol.Marshal(e)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.ws.WriteMessage(websocket.TextMessage, b)
}

type Hub struct {
	mu           sync.RWMutex
	conns        map[string]*connection
	devices      map[string]RegisteredDevice
	registry     *devices.Registry
	logger       *slog.Logger
	upgrader     websocket.Upgrader
	pendingSlots chan struct{}
}

func NewHub(regs []RegisteredDevice, registry *devices.Registry, logger *slog.Logger) *Hub {
	d := make(map[string]RegisteredDevice, len(regs))
	for _, r := range regs {
		d[r.ID] = r
		registry.Register(devices.Device{ID: r.ID, Name: r.Name, PublicKey: r.PublicKey})
	}
	return &Hub{conns: make(map[string]*connection), devices: d, registry: registry, logger: logger, upgrader: websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: 4096}, pendingSlots: make(chan struct{}, maxPendingGlobally)}
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(protocol.MaxFrameBytes)
	_ = ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, data, err := ws.ReadMessage()
	if err != nil {
		_ = ws.Close()
		return
	}
	hello, err := protocol.Decode(bytes.NewReader(data))
	if err != nil || hello.Type != "hello" || hello.DeviceID == "" {
		_ = ws.Close()
		return
	}
	reg, ok := h.devices[hello.DeviceID]
	if !ok || len(reg.PublicKey) != ed25519.PublicKeySize {
		_ = ws.Close()
		return
	}
	challenge, err := auth.NewChallenge()
	if err != nil {
		_ = ws.Close()
		return
	}
	conn := &connection{id: hello.DeviceID, ws: ws, pending: make(map[string]chan pendingResult), done: make(chan struct{})}
	if err = conn.write(protocol.Envelope{Version: protocol.Version, Type: "challenge", DeviceID: hello.DeviceID, Arguments: raw(map[string]string{"challenge": auth.EncodeKey(challenge)})}); err != nil {
		_ = ws.Close()
		return
	}
	_ = ws.SetReadDeadline(time.Now().Add(auth.ChallengeExpiry()))
	_, data, err = ws.ReadMessage()
	if err != nil {
		_ = ws.Close()
		return
	}
	proof, err := protocol.Decode(bytes.NewReader(data))
	if err != nil || proof.Type != "proof" || proof.DeviceID != hello.DeviceID {
		_ = ws.Close()
		return
	}
	var proofArgs struct {
		Signature string `json:"signature"`
	}
	if json.Unmarshal(proof.Arguments, &proofArgs) != nil {
		_ = ws.Close()
		return
	}
	sig, err := auth.DecodeKey(proofArgs.Signature, ed25519.SignatureSize)
	if err != nil || !auth.VerifyChallenge(reg.PublicKey, hello.DeviceID, challenge, sig) {
		h.logger.Warn("agent authentication failed", "device_id", hello.DeviceID)
		_ = ws.Close()
		return
	}
	_ = ws.SetReadDeadline(time.Time{})
	_ = ws.SetReadDeadline(time.Now().Add(65 * time.Second))
	ws.SetPongHandler(func(string) error { return ws.SetReadDeadline(time.Now().Add(65 * time.Second)) })
	h.mu.Lock()
	old := h.conns[hello.DeviceID]
	h.conns[hello.DeviceID] = conn
	h.mu.Unlock()
	if old != nil {
		old.close()
		h.failPending(old, errors.New("agent connection replaced"))
	}
	h.registry.SetOnline(hello.DeviceID, true)
	_ = conn.write(protocol.Envelope{Version: protocol.Version, Type: "welcome", DeviceID: hello.DeviceID})
	go func() {
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-conn.done:
				return
			case <-ticker.C:
				_ = conn.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				conn.writeMu.Lock()
				err := conn.ws.WriteControl(websocket.PingMessage, []byte("ping"), time.Now().Add(10*time.Second))
				conn.writeMu.Unlock()
				if err != nil {
					conn.close()
					return
				}
			}
		}
	}()
	h.logger.Info("agent connected", "device_id", hello.DeviceID, "remote", r.RemoteAddr)
	defer func() {
		h.mu.Lock()
		if h.conns[hello.DeviceID] == conn {
			delete(h.conns, hello.DeviceID)
			h.registry.SetOnline(hello.DeviceID, false)
		}
		h.mu.Unlock()
		h.failPending(conn, errors.New("agent disconnected"))
		conn.close()
		h.logger.Info("agent disconnected", "device_id", hello.DeviceID)
	}()
	for {
		_, data, err = ws.ReadMessage()
		if err != nil {
			return
		}
		e, decErr := protocol.Decode(bytes.NewReader(data))
		if decErr != nil {
			h.logger.Warn("invalid agent frame", "device_id", hello.DeviceID, "error", decErr)
			return
		}
		switch e.Type {
		case "response":
			if e.DeviceID != hello.DeviceID {
				continue
			}
			conn.mu.Lock()
			ch := conn.pending[e.RequestID]
			delete(conn.pending, e.RequestID)
			conn.mu.Unlock()
			if ch != nil {
				select {
				case ch <- pendingResult{response: e}:
				default:
				}
			}
		case "ping":
			h.registry.Touch(hello.DeviceID)
			_ = conn.write(protocol.Envelope{Version: protocol.Version, Type: "pong", DeviceID: hello.DeviceID})
		case "hello":
			var meta struct {
				Version, OS, Arch string
				Commit            string
				Capabilities      []string
			}
			_ = json.Unmarshal(e.Arguments, &meta)
			h.registry.UpdateHeartbeat(hello.DeviceID, meta.Version, meta.OS, meta.Arch, meta.Capabilities, meta.Commit)
		}
	}
}

func (h *Hub) Do(ctx context.Context, deviceID, method string, args any) (out json.RawMessage, resultErr error) {
	started := time.Now()
	id, err := requestID()
	if err != nil {
		return nil, err
	}
	defer func() {
		h.logger.Info("relay request completed", "request_id", id, "client_identity", "mcp-bearer", "device_id", deviceID, "method", method, "success", resultErr == nil, "duration_ms", time.Since(started).Milliseconds())
	}()
	select {
	case h.pendingSlots <- struct{}{}:
	default:
		return nil, errors.New("relay request queue is full")
	}
	defer func() { <-h.pendingSlots }()
	h.mu.RLock()
	c := h.conns[deviceID]
	h.mu.RUnlock()
	if c == nil {
		return nil, fmt.Errorf("device %q is offline", deviceID)
	}
	ch := make(chan pendingResult, 1)
	c.mu.Lock()
	if len(c.pending) >= maxPendingPerDevice {
		c.mu.Unlock()
		return nil, errors.New("device request queue is full")
	}
	c.pending[id] = ch
	c.mu.Unlock()
	b, err := json.Marshal(args)
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, err
	}
	if err = c.write(protocol.Envelope{Version: protocol.Version, Type: "request", RequestID: id, DeviceID: deviceID, Method: method, Arguments: b}); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, err
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if !r.response.OK {
			if r.response.Error == nil {
				return nil, errors.New("agent returned an invalid error response")
			}
			return nil, fmt.Errorf("%s: %s", r.response.Error.Code, r.response.Error.Message)
		}
		return r.response.Result, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		_ = c.write(protocol.Envelope{Version: protocol.Version, Type: "cancel", RequestID: id, DeviceID: deviceID})
		return nil, ctx.Err()
	case <-c.done:
		return nil, errors.New("agent disconnected")
	}
}

func (h *Hub) failPending(c *connection, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ch := range c.pending {
		select {
		case ch <- pendingResult{err: err}:
		default:
		}
		delete(c.pending, id)
	}
}
func (h *Hub) OnlineCount() int { h.mu.RLock(); defer h.mu.RUnlock(); return len(h.conns) }
func (h *Hub) Close() {
	h.mu.Lock()
	conns := make([]*connection, 0, len(h.conns))
	for id, c := range h.conns {
		delete(h.conns, id)
		conns = append(conns, c)
		h.registry.SetOnline(id, false)
	}
	h.mu.Unlock()
	for _, c := range conns {
		c.close()
		h.failPending(c, errors.New("relay is shutting down"))
	}
}
func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func requestID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
