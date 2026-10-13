// Package protocol defines the versioned wire contract shared by relays and agents.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const Version = 1
const MaxFrameBytes = 4 << 20

type Envelope struct {
	Version   int             `json:"version"`
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	DeviceID  string          `json:"device_id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	OK        bool            `json:"ok,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *Error          `json:"error,omitempty"`
	Time      string          `json:"time,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e Envelope) Validate() error {
	if e.Version != Version {
		return fmt.Errorf("unsupported protocol version %d", e.Version)
	}
	switch e.Type {
	case "request":
		if e.RequestID == "" || e.DeviceID == "" || e.Method == "" {
			return errors.New("request requires request_id, device_id, and method")
		}
	case "response":
		if e.RequestID == "" {
			return errors.New("response requires request_id")
		}
		if e.OK && len(e.Result) == 0 {
			return errors.New("successful response requires result")
		}
		if !e.OK && e.Error == nil {
			return errors.New("failed response requires structured error")
		}
	case "hello", "challenge", "proof", "welcome", "ping", "pong", "cancel":
	default:
		return fmt.Errorf("unknown envelope type %q", e.Type)
	}
	return nil
}

func Decode(r io.Reader) (Envelope, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxFrameBytes+1))
	if err != nil {
		return Envelope{}, err
	}
	if len(b) > MaxFrameBytes {
		return Envelope{}, errors.New("frame exceeds maximum size")
	}
	var e Envelope
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return e, err
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return e, errors.New("multiple JSON values")
		}
		return e, err
	}
	if err := e.Validate(); err != nil {
		return e, err
	}
	return e, nil
}

func Marshal(e Envelope) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFrameBytes {
		return nil, errors.New("frame exceeds maximum size")
	}
	return b, nil
}

func SafeText(s string, max int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) > max {
		return s[:max]
	}
	return s
}
