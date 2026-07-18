//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/lcolon231/rmm/agent/internal/config"
)

const (
	serviceName        = "NodeLinkAgent"
	serviceDisplayName = "NodeLink RMM Agent"
	serviceDescription = "NodeLink RMM endpoint agent: enrolls, checks in, and runs signed commands."
)

// IsService reports whether the process was started by the Windows SCM (as
// opposed to being run from a console).
func IsService() (bool, error) {
	return svc.IsWindowsService()
}

// RunService runs the agent under the Windows SCM. Because no console is
// attached, it logs to a rotated file and reads config from beside the binary.
func RunService(version string) error {
	logger, closer, err := NewFileLogger()
	if err != nil {
		return err
	}
	defer closer.Close()

	cfgPath, err := ConfigNextToExe()
	if err != nil {
		logger.Printf("cannot resolve config path: %v", err)
		return err
	}

	logger.Printf("NodeLink RMM agent %s starting as Windows service", version)
	agent := NewAgent(cfgPath, version, logger)
	if err := svc.Run(serviceName, &handler{agent: agent, log: logger}); err != nil {
		logger.Printf("service failed: %v", err)
		return err
	}
	return nil
}

// handler adapts the OS-independent Agent runtime to the SCM lifecycle.
type handler struct {
	agent *Agent
	log   *log.Logger
}

// Execute implements svc.Handler. It starts the runtime, reports Running, and on
// Stop/Shutdown cancels the runtime's context and waits for it to drain (the
// runtime enforces its own in-flight-command grace period).
func (h *handler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- h.agent.Run(ctx) }()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			// The runtime exited on its own (e.g. fatal config error). Report a
			// non-zero exit so the SCM applies the configured recovery action.
			if err != nil {
				h.log.Printf("agent runtime exited: %v", err)
			}
			changes <- svc.Status{State: svc.Stopped}
			return err != nil, 1
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Advertise how long we may take so the SCM waits for the grace.
				waitHint := uint32(h.agent.shutdownGrace/time.Millisecond) + 5000
				changes <- svc.Status{State: svc.StopPending, WaitHint: waitHint}
				cancel()
				<-done
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			default:
				h.log.Printf("unexpected SCM control request #%d", c.Cmd)
			}
		}
	}
}

// Install registers the service to auto-start at boot, configures crash
// recovery, and writes config next to the binary. It is an error to install
// when the service already exists.
func Install(configSrc string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %q is already installed", serviceName)
	}

	// Place (and validate) config beside the binary before creating the service.
	if err := installConfig(exe, configSrc); err != nil {
		return err
	}

	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  serviceDisplayName,
		Description:  serviceDescription,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, "run")
	if err != nil {
		return err
	}
	defer s.Close()

	// Auto-recovery: restart on crash with escalating backoff, resetting the
	// failure counter after a day of stable running.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 24*60*60); err != nil {
		return fmt.Errorf("service created but configuring recovery failed: %w", err)
	}
	return nil
}

// installConfig copies configSrc to config.json beside the binary, validating it
// first. If configSrc is empty, an existing config beside the binary is kept.
func installConfig(exe, configSrc string) error {
	dst := filepath.Join(filepath.Dir(exe), "config.json")

	if configSrc == "" {
		if _, err := os.Stat(dst); err == nil {
			return nil // already present next to the binary
		}
		return fmt.Errorf("no -config provided and no config.json next to %s", exe)
	}

	srcAbs, err := filepath.Abs(configSrc)
	if err != nil {
		return err
	}
	if srcAbs == dst {
		// Already in place; still validate it.
		if _, err := config.Load(dst); err != nil {
			return err
		}
		return nil
	}

	// Validate before copying so a bad config fails at install time.
	if _, err := config.Load(configSrc); err != nil {
		return err
	}
	data, err := os.ReadFile(configSrc)
	if err != nil {
		return fmt.Errorf("read config %s: %w", configSrc, err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return fmt.Errorf("write config %s: %w", dst, err)
	}
	return nil
}

// Uninstall stops (best-effort) and removes the service. It is idempotent: it
// returns nil when the service is not installed.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil // not installed: nothing to do
	}
	defer s.Close()

	if status, err := s.Query(); err == nil && status.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err == nil {
			_ = waitForState(s, svc.Stopped, 20*time.Second)
		}
	}
	return s.Delete()
}

// Start starts the installed service and waits for it to reach Running.
func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed: %w", serviceName, err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return err
	}
	return waitForState(s, svc.Running, 20*time.Second)
}

// Stop stops the running service and waits for it to reach Stopped.
func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %q is not installed: %w", serviceName, err)
	}
	defer s.Close()

	if _, err := s.Control(svc.Stop); err != nil {
		return err
	}
	return waitForState(s, svc.Stopped, 30*time.Second)
}

// waitForState polls the service until it reaches want or the timeout elapses.
func waitForState(s *mgr.Service, want svc.State, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for service state %d (current %d)", want, status.State)
		}
		time.Sleep(300 * time.Millisecond)
	}
}
