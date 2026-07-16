// Command agent is the NodeLink RMM endpoint agent. It enrolls once, then
// checks in on a fixed cadence: reporting telemetry, picking up commands,
// verifying each command's signature before executing it, and reporting results.
//
// It runs in the foreground on any platform (rmm-agent run / -config) and, on
// Windows, can be installed and run as a service via the install|uninstall|
// start|stop subcommands.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/lcolon231/rmm/agent/internal/service"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	// If launched by the Windows SCM, run as a service and nothing else. This
	// is detected from the process environment, not the arguments.
	if isSvc, err := service.IsService(); err == nil && isSvc {
		if err := service.RunService(version); err != nil {
			os.Exit(1) // no console attached; RunService logs to file
		}
		return
	}

	// First non-flag argument selects a subcommand; default is "run" so the
	// existing `rmm-agent -config ...` / `rmm-agent -once` invocations still work.
	args := os.Args[1:]
	sub := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}

	switch sub {
	case "run":
		runForeground(args)
	case "install", "uninstall", "start", "stop":
		runControl(sub, args)
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", sub)
		usage(os.Stderr)
		os.Exit(2)
	}
}

// runForeground runs the check-in loop in the foreground, logging to stdout.
// This preserves the original console behavior exactly.
func runForeground(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "config.json", "path to agent config file")
	once := fs.Bool("once", false, "run a single check-in and exit (useful for testing)")
	_ = fs.Parse(args)

	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	logger.Printf("NodeLink RMM agent %s starting", version)

	agent := service.NewAgent(*configPath, version, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		if err := agent.RunOnce(ctx); err != nil {
			logger.Fatalf("check-in: %v", err)
		}
		return
	}
	if err := agent.Run(ctx); err != nil {
		logger.Fatalf("agent: %v", err)
	}
}

// runControl handles the Windows service-control subcommands. On non-Windows
// platforms these report that service control is unsupported.
func runControl(sub string, args []string) {
	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	configPath := fs.String("config", "config.json",
		"path to the config to install beside the service binary (install only)")
	_ = fs.Parse(args)

	var err error
	switch sub {
	case "install":
		err = service.Install(*configPath)
	case "uninstall":
		err = service.Uninstall()
	case "start":
		err = service.Start()
	case "stop":
		err = service.Stop()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", sub, err)
		os.Exit(1)
	}
	fmt.Printf("%s: ok\n", sub)
}

func usage(w *os.File) {
	fmt.Fprintf(w, `NodeLink RMM agent %s

Usage:
  rmm-agent [run] [-config FILE] [-once]   Run in the foreground (default)
  rmm-agent install   [-config FILE]       Install as a Windows service (auto-start)
  rmm-agent uninstall                      Remove the Windows service (idempotent)
  rmm-agent start                          Start the installed Windows service
  rmm-agent stop                           Stop the running Windows service

The service subcommands are Windows-only. On Linux/macOS the agent runs in the
foreground and is typically supervised by systemd/launchd.
`, version)
}
