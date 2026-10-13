package relay

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/devices"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/transport"
)

type MCP struct {
	Hub     *transport.Hub
	Devices *devices.Registry
	Logger  *slog.Logger
}
type DeviceArgs struct {
	DeviceID string `json:"device_id" jsonschema:"registered target device ID; required for all device operations"`
}
type PathArgs struct {
	DeviceID string `json:"device_id" jsonschema:"registered target device ID"`
	Path     string `json:"path" jsonschema:"absolute filesystem path"`
}
type ListArgs struct {
	DeviceID string `json:"device_id"`
	Path     string `json:"path"`
	Offset   int    `json:"offset,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}
type ReadArgs struct {
	DeviceID string `json:"device_id"`
	Path     string `json:"path"`
	MaxBytes int64  `json:"max_bytes,omitempty"`
}
type SearchArgs struct {
	DeviceID   string `json:"device_id"`
	Path       string `json:"path"`
	Text       string `json:"text"`
	MaxFiles   int    `json:"max_files,omitempty"`
	MaxDepth   int    `json:"max_depth,omitempty"`
	MaxBytes   int64  `json:"max_bytes,omitempty"`
	MaxMatches int    `json:"max_matches,omitempty"`
}
type ReplaceArgs struct {
	DeviceID        string `json:"device_id"`
	Path            string `json:"path"`
	Search          string `json:"search"`
	Replace         string `json:"replace"`
	ExpectedMatches int    `json:"expected_matches" jsonschema:"required; exact number of matches required before any change"`
}
type WriteArgs struct {
	DeviceID      string `json:"device_id"`
	Path          string `json:"path"`
	Content       string `json:"content"`
	CreateParents bool   `json:"create_parents,omitempty"`
}
type MoveArgs struct {
	DeviceID string `json:"device_id"`
	From     string `json:"from"`
	To       string `json:"to"`
}
type RunArgs struct {
	DeviceID         string            `json:"device_id"`
	Command          string            `json:"command"`
	Args             []string          `json:"args,omitempty"`
	Shell            string            `json:"shell,omitempty"`
	WorkingDirectory string            `json:"working_directory,omitempty"`
	Environment      map[string]string `json:"environment,omitempty"`
	TimeoutSeconds   int               `json:"timeout_seconds,omitempty"`
	Stdin            string            `json:"stdin,omitempty"`
	CloseStdin       bool              `json:"close_stdin,omitempty"`
}
type SessionArgs struct {
	DeviceID    string `json:"device_id"`
	SessionID   string `json:"session_id"`
	WaitSeconds int    `json:"wait_seconds,omitempty"`
	Offset      int    `json:"offset,omitempty"`
}
type StdinArgs struct {
	DeviceID  string `json:"device_id"`
	SessionID string `json:"session_id"`
	Data      string `json:"data"`
	Close     bool   `json:"close,omitempty"`
}
type ProcessKillArgs struct {
	DeviceID string `json:"device_id"`
	PID      int    `json:"pid"`
}
type ToolOutput struct {
	Result any `json:"result"`
}

func (m *MCP) Server() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "ato-computer-relay", Version: "0.1.0"}, &mcp.ServerOptions{Instructions: "Private self-hosted computer control relay. Specify device_id explicitly. Computer actions run under policy configured on the Windows agent; commands and writes can change that device."})
	mcp.AddTool(s, &mcp.Tool{Name: "device_list", Description: "List registered devices and online status. Use device_id from this list for all routed operations."}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, []devices.Device, error) {
		m.Logger.Info("mcp tool completed", "client_identity", "mcp-bearer", "method", "device.list", "success", true)
		return nil, m.Devices.List(), nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "system_info", Description: "Get operating system, architecture, hostname, agent and protocol versions from a specific online device."}, func(ctx context.Context, _ *mcp.CallToolRequest, a DeviceArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "system.info", map[string]any{})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "fs_list", Description: "List a page of files and folders at a path allowed by the Windows agent's local policy."}, func(ctx context.Context, _ *mcp.CallToolRequest, a ListArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "fs.list", map[string]any{"path": a.Path, "offset": a.Offset, "limit": a.Limit})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "fs_read", Description: "Read a UTF-8 text file within the agent's configured filesystem roots."}, func(ctx context.Context, _ *mcp.CallToolRequest, a ReadArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "fs.read", map[string]any{"path": a.Path, "max_bytes": a.MaxBytes})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "fs_search", Description: "Search bounded UTF-8 text files under an allowed path. Symlinks are skipped; file, depth, byte, and match limits are enforced."}, func(ctx context.Context, _ *mcp.CallToolRequest, a SearchArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "fs.search", map[string]any{"path": a.Path, "text": a.Text, "max_files": a.MaxFiles, "max_depth": a.MaxDepth, "max_bytes": a.MaxBytes, "max_matches": a.MaxMatches})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "fs_replace", Description: "Replace text in one allowed UTF-8 file atomically, only when the actual match count equals expected_matches."}, func(ctx context.Context, _ *mcp.CallToolRequest, a ReplaceArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "fs.replace", map[string]any{"path": a.Path, "search": a.Search, "replace": a.Replace, "expected_matches": a.ExpectedMatches})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "fs_write", Description: "Write a UTF-8 text file within the agent's configured filesystem roots."}, func(ctx context.Context, _ *mcp.CallToolRequest, a WriteArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "fs.write", map[string]any{"path": a.Path, "content": a.Content, "create_parents": a.CreateParents})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "fs_mkdir", Description: "Create a directory within the agent's configured filesystem roots."}, func(ctx context.Context, _ *mcp.CallToolRequest, a PathArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "fs.mkdir", map[string]any{"path": a.Path, "parents": true})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "fs_move", Description: "Move or rename a file or directory. Source and destination must both be allowed by local policy."}, func(ctx context.Context, _ *mcp.CallToolRequest, a MoveArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "fs.move", map[string]any{"from": a.From, "to": a.To})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "fs_stat", Description: "Check whether a path exists and get basic file metadata."}, func(ctx context.Context, _ *mcp.CallToolRequest, a PathArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "fs.stat", map[string]any{"path": a.Path})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "command_run", Description: "Run a command on a specific Windows device and return bounded stdout, stderr, exit code and duration. Command and shell permissions are enforced by local agent policy."}, func(ctx context.Context, _ *mcp.CallToolRequest, a RunArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "process.run", map[string]any{"command": a.Command, "args": a.Args, "shell": a.Shell, "working_directory": a.WorkingDirectory, "environment": a.Environment, "timeout_seconds": a.TimeoutSeconds, "stdin": a.Stdin})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "process_start", Description: "Start a long-running command and return a session ID for reading output, sending stdin, or terminating it."}, func(ctx context.Context, _ *mcp.CallToolRequest, a RunArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "process.start", map[string]any{"command": a.Command, "args": a.Args, "shell": a.Shell, "working_directory": a.WorkingDirectory, "environment": a.Environment, "timeout_seconds": a.TimeoutSeconds, "close_stdin": a.CloseStdin})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "process_sessions", Description: "List agent-owned process sessions for recovery after reconnect. Read-only; provides session IDs, PIDs, running state and exit codes."}, func(ctx context.Context, _ *mcp.CallToolRequest, a DeviceArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "process.sessions", map[string]any{})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "process_read", Description: "Read accumulated output and status for a process session."}, func(ctx context.Context, _ *mcp.CallToolRequest, a SessionArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "process.read", map[string]any{"session_id": a.SessionID, "wait_seconds": a.WaitSeconds, "offset": a.Offset})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "process_stdin", Description: "Send text to the stdin of a long-running process session."}, func(ctx context.Context, _ *mcp.CallToolRequest, a StdinArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "process.stdin", map[string]any{"session_id": a.SessionID, "data": a.Data, "close": a.Close})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "process_terminate", Description: "Terminate a process session started through this relay."}, func(ctx context.Context, _ *mcp.CallToolRequest, a SessionArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "process.terminate", map[string]any{"session_id": a.SessionID})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "process_list", Description: "List up to 512 processes on a specific device."}, func(ctx context.Context, _ *mcp.CallToolRequest, a DeviceArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "process.list", map[string]any{})
	})
	mcp.AddTool(s, &mcp.Tool{Name: "process_kill", Description: "Terminate a process by PID after checking protected and locally denied process names."}, func(ctx context.Context, _ *mcp.CallToolRequest, a ProcessKillArgs) (*mcp.CallToolResult, ToolOutput, error) {
		return m.call(ctx, a.DeviceID, "process.kill", map[string]any{"pid": a.PID})
	})
	return s
}

func (m *MCP) call(ctx context.Context, deviceID, method string, args any) (*mcp.CallToolResult, ToolOutput, error) {
	start := time.Now()
	res, err := m.Hub.Do(ctx, deviceID, method, args)
	if err == nil {
		var v any
		if e := json.Unmarshal(res, &v); e != nil {
			err = e
		} else {
			m.Logger.Info("mcp tool completed", "client_identity", "mcp-bearer", "device_id", deviceID, "method", method, "success", true, "duration_ms", time.Since(start).Milliseconds())
			return nil, ToolOutput{Result: v}, nil
		}
	}
	m.Logger.Info("mcp tool completed", "client_identity", "mcp-bearer", "device_id", deviceID, "method", method, "success", false, "duration_ms", time.Since(start).Milliseconds(), "error", err)
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, ToolOutput{}, nil
}
