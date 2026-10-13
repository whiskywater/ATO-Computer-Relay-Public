// Command mcpcheck is a small MCP client harness for local/deployment validation.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type bearerTransport struct {
	next  http.RoundTripper
	token string
}

func (b bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(clone)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	url := flag.String("url", "http://127.0.0.1:8443/mcp", "Streamable HTTP MCP endpoint")
	mode := flag.String("mode", "tools", "operation: tools, devices, info, run")
	device := flag.String("device", "", "registered target device ID")
	name := flag.String("token-env", "ATO_MCP_BEARER_TOKEN", "environment variable containing bearer token")
	command := flag.String("command", "", "command or PowerShell script for run mode")
	shell := flag.String("shell", "", "optional shell: powershell, pwsh, or cmd")
	argJSON := flag.String("args", "[]", "JSON array of command arguments")
	cwd := flag.String("cwd", "", "optional working directory")
	timeout := flag.Int("timeout", 0, "optional command timeout in seconds")
	flag.Parse()
	token := os.Getenv(*name)
	if len(token) < 32 {
		return errors.New("bearer token environment variable is missing or too short")
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "ato-mcpcheck", Version: "0.1.0"}, nil)
	httpClient := &http.Client{Transport: bearerTransport{next: http.DefaultTransport, token: token}, Timeout: 5 * time.Minute}
	s, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: *url, HTTPClient: httpClient, DisableStandaloneSSE: true}, nil)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var result any
	switch *mode {
	case "tools":
		result, err = s.ListTools(ctx, &mcp.ListToolsParams{})
	case "devices":
		result, err = s.CallTool(ctx, &mcp.CallToolParams{Name: "device_list", Arguments: map[string]any{}})
	case "info":
		if *device == "" {
			return errors.New("-device is required")
		}
		result, err = s.CallTool(ctx, &mcp.CallToolParams{Name: "system_info", Arguments: map[string]any{"device_id": *device}})
	case "run":
		if *device == "" || *command == "" {
			return errors.New("-device and -command are required")
		}
		var args []string
		if err = json.Unmarshal([]byte(*argJSON), &args); err != nil {
			return fmt.Errorf("parse -args JSON: %w", err)
		}
		result, err = s.CallTool(ctx, &mcp.CallToolParams{Name: "command_run", Arguments: map[string]any{"device_id": *device, "command": *command, "args": args, "shell": *shell, "working_directory": *cwd, "timeout_seconds": *timeout}})
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		return err
	}
	if r, ok := result.(*mcp.CallToolResult); ok && r.IsError {
		return errors.New(toolError(r))
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(strings.TrimSpace(string(b)))
	return nil
}
func toolError(r *mcp.CallToolResult) string {
	for _, c := range r.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			return t.Text
		}
	}
	return "MCP tool returned an error"
}
