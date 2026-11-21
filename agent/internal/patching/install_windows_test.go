//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"context"
	"strings"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
	"github.com/lcolon231/rmm/agent/internal/pwsh/pwshtest"
)

func withRunPS(t *testing.T, fake *pwshtest.Fake) {
	t.Helper()
	orig := runPS
	runPS = fake.Run
	t.Cleanup(func() { runPS = orig })
}

func TestInstallPassesTargetsOutsideTheEncodedScript(t *testing.T) {
	fake := &pwshtest.Fake{Reply: pwshtest.Stdout("progress noise\r\n" +
		`{"status":"succeeded","installed_kbs":["KB5034441"],"failed_kbs":[],"reboot_required":false,"message":"ok"}` + "\r\n")}
	withRunPS(t, fake)

	res, err := Install(context.Background(), InstallTargets{KBIDs: []string{"kb5034441"}})
	if err != nil || res.Status != "succeeded" || len(res.InstalledKBs) != 1 {
		t.Fatalf("Install = (%+v, %v)", res, err)
	}
	calls := fake.Calls()
	if len(calls) != 1 {
		t.Fatalf("runner called %d times", len(calls))
	}
	call := calls[0]
	if !call.Encoded || call.Timeout != installTimeout {
		t.Fatalf("install must run encoded with installTimeout: %+v", call)
	}
	if !strings.HasPrefix(call.Body, psInstallPrefix+"\n") || !strings.HasSuffix(call.Body, psInstallScript) {
		t.Fatal("install body is not the constant prefix plus script")
	}
	if strings.Contains(call.Body, "5034441") {
		t.Fatal("a target identifier leaked into the script text")
	}
	if call.Env["NL_TARGET_KBS"] != "KB5034441" || call.Env["NL_INSTALL_ALL"] != "false" {
		t.Fatalf("targets not passed as env: %v", call.Env)
	}
}

func TestInstallReportsStderrWhenTheScriptPrintsNothing(t *testing.T) {
	withRunPS(t, &pwshtest.Fake{Reply: pwshtest.Exit("", "New-Object : COM class not registered", 1)})
	res, err := Install(context.Background(), InstallTargets{All: true})
	if err == nil || res.Status != "failed" || !strings.Contains(res.Message, "COM class not registered") {
		t.Fatalf("Install = (%+v, %v)", res, err)
	}
}

func TestInstallRejectsInvalidTargetsWithoutRunning(t *testing.T) {
	fake := &pwshtest.Fake{}
	withRunPS(t, fake)
	if _, err := Install(context.Background(), InstallTargets{KBIDs: []string{"KB1'; Remove-Item C:\\"}}); err == nil {
		t.Fatal("Install accepted a hostile target")
	}
	if len(fake.Calls()) != 0 {
		t.Fatal("runner called for invalid targets")
	}
}

func TestScanRunsTheConstantScript(t *testing.T) {
	fake := &pwshtest.Fake{Reply: pwshtest.Stdout(`{"reboot_required":false,"error_code":"","history_error_code":"","missing":[],"installed":[]}`)}
	withRunPS(t, fake)
	if _, _, err := Scan(context.Background()); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	calls := fake.Calls()
	want := pwsh.Script{Body: psScript, Timeout: scanTimeout}
	if len(calls) != 1 || calls[0].Body != want.Body || calls[0].Timeout != want.Timeout || calls[0].Env != nil {
		t.Fatalf("scan calls = %+v", calls)
	}

	withRunPS(t, &pwshtest.Fake{Reply: pwshtest.Exit("", "denied", 1)})
	if _, _, err := Scan(context.Background()); err == nil {
		t.Fatal("Scan ignored a failed run")
	}
}
