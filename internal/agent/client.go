// Package agent implements the reconnecting Windows-friendly outbound relay client.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/auth"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/executor"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/protocol"
)

var Version = "0.1.0"
var Commit = "unknown"

const maxWorkers = 32

type Client struct {
	URL            string
	DeviceID, Name string
	PrivateKey     ed25519.PrivateKey
	Executor       *executor.Executor
	Logger         *slog.Logger
	ReconnectMax   time.Duration
	dialer         *websocket.Dialer
}

func (c *Client) Run(ctx context.Context) error {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.ReconnectMax <= 0 {
		c.ReconnectMax = 60 * time.Second
	}
	if c.dialer == nil {
		c.dialer = &websocket.Dialer{HandshakeTimeout: 15 * time.Second, Proxy: http.ProxyFromEnvironment}
	}
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		c.Logger.Warn("agent disconnected; retrying", "error", err, "backoff", backoff)
		delay := backoff * time.Duration(75+rand.IntN(51)) / 100
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		backoff *= 2
		if backoff > c.ReconnectMax {
			backoff = c.ReconnectMax
		}
	}
}

func (c *Client) runOnce(parent context.Context) error {
	conn, _, err := c.dialer.DialContext(parent, c.URL, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetReadLimit(protocol.MaxFrameBytes)
	writeMu := sync.Mutex{}
	write := func(e protocol.Envelope) error {
		b, er := protocol.Marshal(e)
		if er != nil {
			return er
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteMessage(websocket.TextMessage, b)
	}
	if err = write(protocol.Envelope{Version: protocol.Version, Type: "hello", DeviceID: c.DeviceID}); err != nil {
		return err
	}
	_, data, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	challenge, err := protocol.Decode(bytes.NewReader(data))
	if err != nil || challenge.Type != "challenge" || challenge.DeviceID != c.DeviceID {
		return errors.New("relay challenge rejected")
	}
	var cdata struct {
		Challenge string `json:"challenge"`
	}
	if err = json.Unmarshal(challenge.Arguments, &cdata); err != nil {
		return err
	}
	nonce, err := auth.DecodeKey(cdata.Challenge, 32)
	if err != nil {
		return err
	}
	sig := auth.SignChallenge(c.PrivateKey, c.DeviceID, nonce)
	if err = write(protocol.Envelope{Version: protocol.Version, Type: "proof", DeviceID: c.DeviceID, Arguments: raw(map[string]string{"signature": auth.EncodeKey(sig)})}); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	_, data, err = conn.ReadMessage()
	if err != nil {
		return err
	}
	welcome, err := protocol.Decode(bytes.NewReader(data))
	if err != nil || welcome.Type != "welcome" {
		return errors.New("relay authentication failed")
	}
	_ = conn.SetReadDeadline(time.Time{})
	_ = conn.SetReadDeadline(time.Now().Add(65 * time.Second))
	conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(65 * time.Second)) })
	ctx, cancel := context.WithCancel(parent)
	slots := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup
	active := sync.Map{}
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-watchDone:
		}
	}()
	defer close(watchDone)
	defer func() { cancel(); _ = conn.Close(); wg.Wait() }()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	pingErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ping.C:
				if e := write(protocol.Envelope{Version: protocol.Version, Type: "ping", DeviceID: c.DeviceID}); e != nil {
					select {
					case pingErr <- e:
					default:
					}
					cancel()
					return
				}
			}
		}
	}()
	meta, _ := json.Marshal(map[string]any{"version": Version, "commit": Commit, "os": runtime.GOOS, "arch": runtime.GOARCH, "capabilities": []string{"system.info", "fs.list", "fs.read", "fs.search", "fs.replace", "fs.write", "fs.mkdir", "fs.move", "fs.stat", "process.run", "process.start", "process.read", "process.sessions", "process.stdin", "process.terminate", "process.list", "process.kill"}})
	_ = write(protocol.Envelope{Version: protocol.Version, Type: "hello", DeviceID: c.DeviceID, Arguments: meta})
	for {
		select {
		case e := <-pingErr:
			return e
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_, data, err = conn.ReadMessage()
		if err != nil {
			return err
		}
		e, er := protocol.Decode(bytes.NewReader(data))
		if er != nil {
			return er
		}
		switch e.Type {
		case "request":
			if e.DeviceID != c.DeviceID {
				continue
			}
			if _, loaded := active.LoadOrStore(e.RequestID, true); loaded {
				continue
			}
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			default:
				return errors.New("relay exceeded the agent request queue")
			}
			reqCtx, reqCancel := context.WithCancel(ctx)
			active.Store(e.RequestID, reqCancel)
			wg.Add(1)
			go func(req protocol.Envelope) {
				defer wg.Done()
				defer func() { <-slots; active.Delete(req.RequestID); reqCancel() }()
				result, callErr := c.Executor.Handle(reqCtx, req.Method, req.Arguments)
				res := protocol.Envelope{Version: protocol.Version, Type: "response", RequestID: req.RequestID, DeviceID: c.DeviceID, OK: callErr == nil}
				if callErr != nil {
					res.Error = &protocol.Error{Code: "execution_error", Message: callErr.Error()}
				} else {
					res.Result, _ = json.Marshal(result)
				}
				if er := write(res); er != nil {
					cancel()
				}
			}(e)
		case "cancel":
			if v, ok := active.Load(e.RequestID); ok {
				if f, ok := v.(context.CancelFunc); ok {
					f()
				}
			}
		case "pong":
			_ = conn.SetReadDeadline(time.Now().Add(65 * time.Second))
		}
	}
}

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
