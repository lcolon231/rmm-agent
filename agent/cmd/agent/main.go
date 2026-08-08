// SPDX-License-Identifier: AGPL-3.0-only
// Command agent is the NodeLink RMM endpoint agent. It enrolls once, then
// checks in on a fixed cadence: reporting telemetry, picking up commands,
// verifying each command's signature before executing it, and reporting results.
//
// It runs in the foreground on any platform (rmm-agent run / -config) and, on
// Windows, can be installed and run as a service via the install|uninstall|
// start|stop subcommands.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/lcolon231/rmm/agent/internal/config"
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
	case "enroll":
		runEnroll(args)
	case "validate-upgrade":
		runValidateUpgrade(args)
	case "version":
		os.Exit(runVersion(version, args, os.Stdout, os.Stderr))
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

// unstampedVersion is the value `version` carries when a build did not pass
// -ldflags "-X main.version=...". A release artifact must never report it, so
// the release build and the installer compile both refuse it (issue #179).
const unstampedVersion = "0.1.0-dev"

// runVersion prints the version stamped into this binary and, with -expect,
// asserts it matches a caller-supplied value. Release builds and the installer
// compile use the assertion so an unstamped or mismatched binary can never be
// published or wrapped in an installer. Returns the process exit code.
func runVersion(reported string, args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(errOut)
	expect := fs.String("expect", "", "fail unless the embedded version equals this value")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fmt.Fprintln(out, reported)
	if *expect == "" {
		return 0
	}
	if reported == unstampedVersion {
		fmt.Fprintf(errOut,
			"version: binary is unstamped (%s); rebuild with -ldflags \"-X main.version=%s\"\n",
			reported, *expect)
		return 1
	}
	if reported != *expect {
		fmt.Fprintf(errOut, "version: embedded version %q does not match expected %q\n", reported, *expect)
		return 1
	}
	return 0
}

// runValidateUpgrade is a read-only installer preflight. It never prints file
// contents and never decrypts identity data; the latter belongs to the Windows
// service account when the upgraded service starts.
func runValidateUpgrade(args []string) {
	fs := flag.NewFlagSet("validate-upgrade", flag.ExitOnError)
	configPath := fs.String("config", "config.json", "path to the existing token-free config")
	_ = fs.Parse(args)

	if err := config.ValidateTokenFreeUpgradeState(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "validate-upgrade: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("validate-upgrade: ok")
}

func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	serverURL := fs.String("server", "", "management server URL (HTTPS; loopback HTTP allowed for development)")
	configPath := fs.String("config", "config.json", "path for token-free config and protected identity")
	agentName := fs.String("name", "", "optional agent display name")
	tokenEnv := fs.String("token-env", "AGENT_ENROLLMENT_TOKEN", "environment variable containing the temporary token")
	tokenFile := fs.String("token-file", "", "restricted file containing the temporary token")
	tokenStdin := fs.Bool("token-stdin", false, "read one token line from standard input")
	nonInteractive := fs.Bool("non-interactive", false, "fail instead of prompting when no token source is available")
	_ = fs.Parse(args)

	if err := validateServerURL(*serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "enroll: %v\n", err)
		os.Exit(2)
	}
	token, err := enrollmentToken(*tokenEnv, *tokenFile, *tokenStdin, *nonInteractive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enroll: %v\n", err)
		os.Exit(2)
	}
	if err := config.SaveInstallConfig(*configPath, strings.TrimRight(*serverURL, "/")); err != nil {
		fmt.Fprintf(os.Stderr, "enroll: save token-free config: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	identity, err := service.EnrollIdentity(
		ctx,
		strings.TrimRight(*serverURL, "/"),
		token,
		*agentName,
		*configPath,
		version,
	)
	token = "" // best-effort lifetime reduction; Go does not guarantee memory wiping.
	if err != nil {
		fmt.Fprintf(os.Stderr, "enroll: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("enrolled agent %s; protected identity saved to %s\n", identity.AgentID, config.IdentityPath(*configPath))
}

func enrollmentToken(envName, filePath string, fromStdin, nonInteractive bool) (string, error) {
	if envName != "" {
		if value := strings.TrimSpace(os.Getenv(envName)); value != "" {
			return value, nil
		}
	}
	if filePath != "" {
		info, err := os.Stat(filePath)
		if err != nil {
			return "", fmt.Errorf("inspect token file: %w", err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return "", fmt.Errorf("token file permissions are too broad; require mode 0600")
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		if value := strings.TrimSpace(string(data)); value != "" {
			return value, nil
		}
		return "", fmt.Errorf("token file is empty")
	}
	if fromStdin {
		value, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("read token from stdin: %w", err)
		}
		return strings.TrimSpace(value), nil
	}
	if nonInteractive {
		return "", fmt.Errorf("no token available; set %s, --token-file, or --token-stdin", envName)
	}
	fmt.Fprint(os.Stderr, "Enrollment token (input hidden): ")
	value, err := readSecret()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("enrollment token is required")
	}
	return strings.TrimSpace(value), nil
}

func validateServerURL(value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("--server must be an origin URL without credentials, query, or fragment")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if parsed.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return fmt.Errorf("--server must use HTTPS (HTTP is allowed only for loopback development)")
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
  rmm-agent enroll --server URL [--token-env NAME | --token-file FILE | --token-stdin]
  rmm-agent validate-upgrade [-config FILE] Read-only installer upgrade preflight
  rmm-agent version [-expect VERSION]      Print (and optionally assert) the build version
  rmm-agent install   [-config FILE]       Install as a Windows service (auto-start)
  rmm-agent uninstall                      Remove the Windows service (idempotent)
  rmm-agent start                          Start the installed Windows service
  rmm-agent stop                           Stop the running Windows service

Enrollment tokens are never accepted as command-line values. Use an environment
variable populated by a secret manager, a mode-0600 secret file, standard input,
or the hidden interactive prompt. Service subcommands are Windows-only.
`, version)
}
