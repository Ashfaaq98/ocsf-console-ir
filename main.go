package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Ashfaaq98/ocsf-console-ir/cmd"
)

// These are set via -ldflags "-X main.Version=... -X main.BuildTime=...".
var Version = "dev"
var BuildTime = ""

func main() {
	// Wire build metadata into the CLI so `--version` and `version` subcommand work.
	cmd.SetVersion(Version, BuildTime)

	// Set up context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	// Execute the root command with context
	if err := cmd.Execute(ctx); err != nil {
		os.Exit(1)
	}
}