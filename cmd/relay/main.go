package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/auth"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/config"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/devices"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/relay"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/transport"
)

var version = "0.1.0"
var commit = "unknown"

func main() {
	configPath := flag.String("config", "config/relay.json", "relay JSON configuration path")
	flag.Parse()
	if flag.Arg(0) == "version" {
		fmt.Printf("relay %s (%s) protocol %d\n", version, commit, 1)
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	cfg, err := config.LoadRelay(*configPath)
	fatalIf(err)
	if cfg.MCPBearerToken == "" {
		fatalIf(fmt.Errorf("ATO_MCP_BEARER_TOKEN must be configured with at least 32 random characters"))
	}
	registered := make([]transport.RegisteredDevice, 0, len(cfg.Devices))
	for _, d := range cfg.Devices {
		if d.Revoked {
			continue
		}
		pub, e := auth.DecodeKey(d.PublicKey, ed25519.PublicKeySize)
		fatalIf(e)
		registered = append(registered, transport.RegisteredDevice{ID: d.ID, Name: d.Name, PublicKey: ed25519.PublicKey(pub)})
	}
	registry := devices.NewRegistry()
	hub := transport.NewHub(registered, registry, logger)
	mcpServer := (&relay.MCP{Hub: hub, Devices: registry, Logger: logger}).Server()
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 1 << 20, PropagateRequestCancellation: true})
	secured, err := auth.BearerMiddleware(cfg.MCPBearerToken, mcpHandler)
	fatalIf(err)
	mux := http.NewServeMux()
	mux.Handle("/agent/ws", hub)
	mux.Handle("/mcp", secured)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"alive": true, "version": version, "commit": commit, "protocol_version": 1})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if len(registered) == 0 {
			http.Error(w, "no registered devices", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": true, "registered_devices": len(registered), "online_devices": hub.OnlineCount()})
	})
	srv := &http.Server{Addr: cfg.ListenAddress, Handler: requestLog(logger, mux), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 32 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		hub.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	logger.Info("relay starting", "listen_address", cfg.ListenAddress, "registered_devices", len(registered), "version", version, "protocol_version", 1)
	var serveErr error
	cert, key := os.Getenv("ATO_RELAY_TLS_CERT"), os.Getenv("ATO_RELAY_TLS_KEY")
	if (cert == "") != (key == "") {
		fatalIf(fmt.Errorf("both ATO_RELAY_TLS_CERT and ATO_RELAY_TLS_KEY are required for native TLS"))
	}
	if cert == "" && !loopback(cfg.ListenAddress) && cfg.PublicURL == "" {
		fatalIf(fmt.Errorf("non-loopback listen requires an HTTPS public_url for a TLS reverse proxy or native TLS certificates"))
	}
	if cert != "" && key != "" {
		serveErr = srv.ListenAndServeTLS(cert, key)
	} else {
		serveErr = srv.ListenAndServe()
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		fatalIf(serveErr)
	}
}
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func requestLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		if r.URL.Path != "/mcp" {
			log.Info("http request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(start).Milliseconds())
		}
	})
}
func fatalIf(err error) {
	if err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}
