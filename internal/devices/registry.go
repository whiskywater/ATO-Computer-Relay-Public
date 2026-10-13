package devices

import (
	"crypto/ed25519"
	"sync"
	"time"
)

type Device struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Online         bool              `json:"online"`
	ConnectedSince time.Time         `json:"connected_since,omitempty"`
	LastSeen       time.Time         `json:"last_seen,omitempty"`
	AgentVersion   string            `json:"agent_version,omitempty"`
	AgentCommit    string            `json:"agent_commit,omitempty"`
	OS             string            `json:"os,omitempty"`
	Architecture   string            `json:"architecture,omitempty"`
	Capabilities   []string          `json:"capabilities,omitempty"`
	PublicKey      ed25519.PublicKey `json:"-"`
}

type Registry struct {
	mu      sync.RWMutex
	devices map[string]Device
}

func NewRegistry() *Registry { return &Registry{devices: make(map[string]Device)} }
func (r *Registry) Register(d Device) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev := r.devices[d.ID]
	if prev.Name != "" && d.Name == "" {
		d.Name = prev.Name
	}
	r.devices[d.ID] = d
}
func (r *Registry) SetOnline(id string, online bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.devices[id]
	d.ID = id
	d.Online = online
	d.LastSeen = time.Now().UTC()
	if online {
		d.ConnectedSince = d.LastSeen
	}
	r.devices[id] = d
}
func (r *Registry) Touch(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.devices[id]
	d.ID = id
	d.LastSeen = time.Now().UTC()
	r.devices[id] = d
}
func (r *Registry) UpdateHeartbeat(id, version, goos, arch string, capabilities []string, commits ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.devices[id]
	d.ID = id
	d.Online = true
	d.LastSeen = time.Now().UTC()
	d.AgentVersion = version
	if len(commits) > 0 {
		d.AgentCommit = commits[0]
	}
	d.OS = goos
	d.Architecture = arch
	d.Capabilities = append([]string(nil), capabilities...)
	r.devices[id] = d
}
func (r *Registry) List() []Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Device, 0, len(r.devices))
	for _, d := range r.devices {
		d.PublicKey = nil
		d.Capabilities = append([]string(nil), d.Capabilities...)
		out = append(out, d)
	}
	return out
}
func (r *Registry) Get(id string) (Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.devices[id]
	d.PublicKey = nil
	return d, ok
}
