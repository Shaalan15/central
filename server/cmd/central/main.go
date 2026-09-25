// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Command central is the Central control-plane server: it serves the web UI and API,
// accepts agent connections, and dispatches commands to managed servers.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Shaalan15/central/server/internal/app"
	"github.com/Shaalan15/central/server/internal/config"
	"github.com/Shaalan15/central/server/internal/logging"
	"github.com/Shaalan15/central/server/internal/setup"
)

// Set at build time via -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "none"
)

const usage = `Central — fleet management control plane

Usage:
  central serve [flags]        run the server
  central healthcheck [--url]  exit 0 if the server answers /healthz (for container health checks)
  central setup-token          print the one-time setup token of a fresh install
  central version              print version information

Run "central serve --help" for server flags. Configuration is read from
<data dir>/central.toml and CENTRAL_* environment variables (see docs/deployment/).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "healthcheck":
		err = healthcheck(os.Args[2:])
	case "setup-token":
		err = setupToken(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("central %s (commit %s, %s)\n", version, commit, runtime.Version())
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "central:", err)
		os.Exit(1)
	}
}

func serverFlags(fs *flag.FlagSet) *config.Flags {
	f := &config.Flags{}
	fs.StringVar(&f.ConfigFile, "config", "", "config file (default <data dir>/central.toml)")
	fs.StringVar(&f.DataDir, "data-dir", "", "data directory (default /var/lib/central, or ./.central with --dev)")
	fs.BoolVar(&f.Dev, "dev", false, "development mode: file-backed in-memory store, relaxed cookies on http://localhost")
	fs.StringVar(&f.HTTPAddr, "http-addr", "", "UI/API listen address (default :8080)")
	fs.StringVar(&f.AgentAddr, "agent-addr", "", "agent listen address (default :9443)")
	return f
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	flags := serverFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*flags, os.Getenv)
	if err != nil {
		return err
	}
	log := logging.New(os.Stderr, cfg.Log.Format, cfg.Log.Level)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := app.New(ctx, &cfg, log, app.Build{Version: version, Commit: commit})
	if err != nil {
		return err
	}
	return a.Run(ctx)
}

func healthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:8080/healthz", "health endpoint to probe")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", resp.Status)
	}
	return nil
}

func setupToken(args []string) error {
	fs := flag.NewFlagSet("setup-token", flag.ExitOnError)
	flags := serverFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*flags, os.Getenv)
	if err != nil {
		return err
	}
	tok, err := setup.ReadTokenFile(cfg.DataDir)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no setup token: setup is complete or the server has not started yet")
	}
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}
