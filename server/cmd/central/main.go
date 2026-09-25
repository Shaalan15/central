// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Command central is the Central control-plane server: it serves the web UI and API,
// accepts agent connections, and dispatches commands to managed servers.
package main

import (
	"fmt"
	"os"
)

// Set at build time via -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "none"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("central %s (%s)\n", version, commit)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: central <command>\n\ncommands:\n  version   print version information")
	os.Exit(2)
}
