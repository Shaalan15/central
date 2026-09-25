// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Command central-sim runs simulated agents that speak the real agent protocol.
// It exists for UI development, end-to-end tests and load tests before the real
// agent is available. It is never shipped to managed servers.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "central-sim: not implemented yet (milestone M10)")
	os.Exit(1)
}
