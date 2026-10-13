package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/agent"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/auth"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/config"
	"github.com/whiskywater/ATO-Computer-Relay-Public/internal/executor"
)

func main() {
	configPath := flag.String("config", "config/agent.json", "agent JSON configuration path")
	keygen := flag.Bool("keygen", false, "generate a new Ed25519 device keypair")
	keyOut := flag.String("key-out", "data/device.key", "private key output path for -keygen")
	superviseJobs := flag.Bool("supervise-jobs", false, "run separately scheduled job supervisor")
	flag.Parse()
	if *keygen {
		pub, priv, err := auth.GenerateDeviceKey()
		fatalIf(err)
		if err = os.MkdirAll(dir(*keyOut), 0700); err != nil {
			fatalIf(err)
		}
		if err = os.WriteFile(*keyOut, []byte(auth.EncodeKey(priv)+"\n"), 0600); err != nil {
			fatalIf(err)
		}
		fmt.Printf("public_key=%s\nprivate_key_file=%s\n", auth.EncodeKey(pub), *keyOut)
		return
	}
	cfg, err := config.LoadAgent(*configPath)
	fatalIf(err)
	if *superviseJobs {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		fatalIf(executor.RunSupervisor(ctx, cfg.Policy, agent.Version, agent.Commit))
		return
	}
	var loggerOut io.Writer = os.Stderr
	var logFile *os.File
	if cfg.LogFile != "" {
		if err = os.MkdirAll(filepath.Dir(cfg.LogFile), 0700); err != nil {
			fatalIf(err)
		}
		logFile, err = os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		fatalIf(err)
		defer logFile.Close()
		loggerOut = logFile
	}
	logger := slog.New(slog.NewJSONHandler(loggerOut, nil))
	priv, err := config.ReadPrivateKey(cfg.PrivateKeyFile)
	fatalIf(err)
	execEngine := executor.New(cfg.Policy, agent.Version)
	execEngine.Commit = agent.Commit
	defer execEngine.Close()
	client := &agent.Client{URL: cfg.RelayURL, DeviceID: cfg.DeviceID, Name: cfg.DeviceName, PrivateKey: ed25519.PrivateKey(priv), Executor: execEngine, Logger: logger, ReconnectMax: cfg.ReconnectMax}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("agent starting", "device_id", cfg.DeviceID, "relay_url", cfg.RelayURL, "version", agent.Version, "commit", agent.Commit)
	run := func(runCtx context.Context) error { return client.Run(runCtx) }
	if agent.IsWindowsService() {
		err = agent.RunWindowsService("ATOComputerAgent", run)
	} else {
		err = run(ctx)
	}
	if err != nil {
		fatalIf(err)
	}
}
func dir(path string) string { return filepath.Dir(path) }
func fatalIf(err error) {
	if err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}
