package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/policy"
)

const supervisorAddress = "127.0.0.1:43879"

type supervisorRequest struct {
	Method string          `json:"method"`
	Args   json.RawMessage `json:"args"`
}
type supervisorReply struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

func supervisorTokenFile(p policy.Policy) (string, error) {
	if p.SessionJournalDir == "" {
		return "", errors.New("session journal directory is required")
	}
	base, err := p.CheckPath(p.SessionJournalDir, true)
	if err != nil {
		return "", err
	}
	return filepath.Join(base, ".supervisor-token"), nil
}
func readSupervisorToken(p policy.Policy) (string, error) {
	path, err := supervisorTokenFile(p)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if len(token) != 64 {
		return "", errors.New("invalid supervisor token")
	}
	if _, err = hex.DecodeString(token); err != nil {
		return "", err
	}
	return token, nil
}
func ensureSupervisorToken(p policy.Policy) (string, error) {
	path, err := supervisorTokenFile(p)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err == nil {
		_, err = f.Write([]byte(hex.EncodeToString(b)))
		closeErr := f.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
	} else if !os.IsExist(err) {
		return "", err
	}
	return readSupervisorToken(p)
}

// RunSupervisor is deliberately a separate Windows scheduled task/process.
// Restarting the ATO connection agent does not close this executor or its jobs.
func RunSupervisor(ctx context.Context, p policy.Policy, version, commit string) error {
	if !p.SupervisorEnabled {
		return errors.New("supervisor is not enabled by local policy")
	}
	token, err := ensureSupervisorToken(p)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", supervisorAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	eng := New(p, version)
	eng.Commit = commit
	eng.supervisorHost = true
	defer eng.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/execute", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			http.Error(w, "method not allowed", 405)
			return
		}
		supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		defer r.Body.Close()
		var req supervisorRequest
		decoder := json.NewDecoder(io.LimitReader(r.Body, 300<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		switch req.Method {
		case "process.start", "process.read", "process.sessions", "process.stdin", "process.terminate":
		default:
			http.Error(w, "unsupported supervisor operation", 403)
			return
		}
		result, err := eng.Handle(r.Context(), req.Method, req.Args)
		reply := supervisorReply{OK: err == nil}
		if err != nil {
			reply.Error = err.Error()
		} else {
			reply.Result, _ = json.Marshal(result)
		}
		_ = json.NewEncoder(w).Encode(reply)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 24 * time.Second, WriteTimeout: 26 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (x *Executor) requestSupervisor(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	token, err := readSupervisorToken(x.Policy)
	if err != nil {
		return nil, fmt.Errorf("durable job supervisor token unavailable: %w", err)
	}
	body, err := json.Marshal(supervisorRequest{Method: method, Args: raw})
	if err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(callCtx, "POST", "http://"+supervisorAddress+"/execute", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	// Force loopback, ignoring HTTP_PROXY and HTTP(S)_PROXY.
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}, Timeout: 25 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("durable job supervisor unavailable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("durable job supervisor HTTP %d", resp.StatusCode)
	}
	var reply supervisorReply
	if err = json.NewDecoder(io.LimitReader(resp.Body, 300<<10)).Decode(&reply); err != nil {
		return nil, err
	}
	if !reply.OK {
		return nil, errors.New(reply.Error)
	}
	var v any
	if err = json.Unmarshal(reply.Result, &v); err != nil {
		return nil, err
	}
	return v, nil
}

// Redirect only noninteractive closed-stdin jobs; interactive sessions remain
// agent-owned. Keep all validation on the independently supervised executor.
func (x *Executor) supervisorDispatch(ctx context.Context, method string, raw json.RawMessage) (any, bool, error) {
	if !x.Policy.SupervisorEnabled || x.supervisorHost {
		return nil, false, nil
	}
	switch method {
	case "process.start":
		var a commandArgs
		if err := decode(raw, &a); err != nil {
			return nil, true, err
		}
		if !a.CloseStdin {
			return nil, false, nil
		}
		v, err := x.requestSupervisor(ctx, method, raw)
		return v, true, err
	case "process.read", "process.stdin", "process.terminate":
		v, err := x.requestSupervisor(ctx, method, raw)
		if err == nil {
			return v, true, nil
		}
		// Local sessions, and completed archived sessions, remain accessible.
		// If no local record exists the original supervisor error is returned
		// instead of falsely declaring a durable process terminated.
		var a struct {
			SessionID string `json:"session_id"`
		}
		if decode(raw, &a) != nil {
			return nil, true, err
		}
		if x.get(a.SessionID) != nil {
			return nil, false, nil
		}
		if method == "process.read" {
			if _, archiveErr := x.archivedStatus(a.SessionID); archiveErr == nil {
				return nil, false, nil
			}
		}
		return nil, true, err
	case "process.sessions":
		v, err := x.requestSupervisor(ctx, method, raw)
		if err != nil {
			return nil, false, nil
		} // retain archived browsing when offline
		base := x.listSessions()
		local, ok := base["sessions"].([]map[string]any)
		if ok {
			_ = local
		}
		// JSON round trip avoids relying on the private anonymous list item type.
		blob, _ := json.Marshal(base["sessions"])
		var older []map[string]any
		_ = json.Unmarshal(blob, &older)
		liveMap, ok := v.(map[string]any)
		if !ok {
			return nil, false, nil
		}
		liveAny, ok := liveMap["sessions"].([]any)
		if !ok {
			return nil, false, nil
		}
		seen := make(map[string]bool, len(liveAny))
		merged := make([]any, 0, len(liveAny)+len(older))
		for _, session := range liveAny {
			item, ok := session.(map[string]any)
			if !ok {
				continue
			}
			id, _ := item["session_id"].(string)
			seen[id] = true
			merged = append(merged, item)
		}
		for _, item := range older {
			id, _ := item["session_id"].(string)
			if !seen[id] {
				merged = append(merged, item)
			}
		}
		return map[string]any{"sessions": merged}, true, nil
	}
	return nil, false, nil
}
