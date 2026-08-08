; NodeLink RMM Agent — graphical Windows installer.
; SPDX-License-Identifier: AGPL-3.0-only
;
; Wraps the existing Go agent binary in an Inno Setup installer so a
; non-technical person can install the agent without touching a terminal.
; Fresh installs enroll with a one-time token; upgrades preserve the existing
; protected identity and token-free configuration. The production
; management-server origin is compiled into this installer.
;
; The installer does NOT reimplement any service logic. It shells out to the
; agent's own CLI verbs (install/start/uninstall — see
; agent/internal/service/service_windows.go), which own service registration,
; auto-recovery configuration, and idempotent removal.
;
; Build (see installer/README.md):
;   set NODELINK_VERSION=0.1.0
;   ISCC NodeLinkAgent.iss
;
; The agent binary is expected at ..\agent\bin\rmm-agent-windows-amd64.exe
; (the agent/build.sh output); override with /DAgentExe=<path>.

#define VersionEnv GetEnv("NODELINK_VERSION")
#if VersionEnv == ""
  #define MyVersion "0.0.0-dev"
#else
  #define MyVersion VersionEnv
#endif

#ifndef AgentExe
  #define AgentExe "..\agent\bin\rmm-agent-windows-amd64.exe"
#endif

; Refuse to wrap a binary that is not stamped with this installer's version
; (issue #179). The agent asserts its own -ldflags version through
; `rmm-agent version -expect <version>`, exiting non-zero when it is unstamped
; (the 0.1.0-dev fallback) or built for a different version — so an installer
; can never ship a binary that will report something other than what its name,
; AppVersion, and release evidence claim. Enforced whenever NODELINK_VERSION is
; set, which covers every release and CI compile; a bare local ISCC run with no
; version in the environment is still allowed to produce a scratch installer.
#if VersionEnv != ""
  #if Pos(":", AgentExe) == 0
    #define AgentExeToVerify AddBackslash(SourcePath) + AgentExe
  #else
    #define AgentExeToVerify AgentExe
  #endif
  #define AgentVersionCheck Exec(AgentExeToVerify, "version -expect " + MyVersion, SourcePath, 0)
  #if AgentVersionCheck != 0
    #error The agent binary does not report NODELINK_VERSION. Rebuild it with -ldflags "-X main.version=$NODELINK_VERSION" before compiling this installer.
  #endif
#endif

#define ProductionServerURL "https://nodelink-backend-733e.onrender.com"

; Personalized-installer sidecar (issue #9). A dashboard-generated download
; bundles this file next to Setup.exe carrying a short-lived, single-use
; enrollment token, so the person running the installer never sees or types a
; token. Read from {src} (the folder Setup.exe runs from); absent for a plain
; stock installer, which falls back to the interactive token prompt.
#define SidecarTokenFile "nodelink-enroll.token"
#define UpgradeValidatorExe "rmm-agent-upgrade-check.exe"

[Setup]
; Fixed GUID so upgrades/uninstalls always target the same installed app.
AppId={{20580A78-1C58-45AA-B0FD-EE6C9B075F3A}
AppName=NodeLink RMM Agent
AppVersion={#MyVersion}
AppPublisher=NodeLink
AppCopyright=Copyright (c) 2026 Luis Colon
LicenseFile=..\LICENSE
DefaultDirName={autopf}\NodeLink\Agent
DisableProgramGroupPage=yes
; Registering a Windows service requires elevation; run the whole installer
; elevated via UAC.
PrivilegesRequired=admin
OutputDir=Output
OutputBaseFilename=NodeLinkAgentSetup-{#MyVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; The agent binary is amd64-only (see agent/build.sh).
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\rmm-agent.exe
UninstallDisplayName=NodeLink RMM Agent

[Messages]
; The standard "Setup Completed" page, with a message that tells the user what
; actually happened: the agent is installed, enrolled, and running as a service.
FinishedLabelNoIcons=Setup has finished installing [name] on your computer.%n%nThe agent is installed, enrolled with your NodeLink server, and running in the background as the Windows service "NodeLink RMM Agent". It starts automatically at boot — no further action is needed on this machine.
FinishedLabel=Setup has finished installing [name] on your computer.%n%nThe agent is installed, enrolled with your NodeLink server, and running in the background as the Windows service "NodeLink RMM Agent". It starts automatically at boot — no further action is needed on this machine.

[Files]
Source: "{#AgentExe}"; DestDir: "{app}"; DestName: "rmm-agent.exe"; Flags: ignoreversion
; The same release binary is extracted to {tmp} only for the read-only upgrade
; preflight that runs before ssInstall changes the service or install dir.
Source: "{#AgentExe}"; DestDir: "{tmp}"; DestName: "{#UpgradeValidatorExe}"; Flags: dontcopy

[UninstallRun]
; Stop + deregister the service while rmm-agent.exe still exists on disk.
; `uninstall` is idempotent (agent code returns success when the service is
; absent), so re-running a partial uninstall is safe.
Filename: "{app}\rmm-agent.exe"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveNodeLinkAgentService"

[UninstallDelete]
; Files the installer/agent create at runtime (not tracked by [Files]).
; identity.json holds the machine's enrolled identity — removing it means a
; reinstall re-enrolls with a fresh token, which is the expected clean-slate
; behavior for "uninstall".
Type: files; Name: "{app}\config.json"
Type: files; Name: "{app}\identity.json"
Type: files; Name: "{app}\seen_commands.json"
Type: files; Name: "{app}\monitoring_state.json"
Type: dirifempty; Name: "{app}"

[Code]
const
  InstallModeFresh = 0;
  InstallModeUpgrade = 1;
  InstallModeBlocked = 2;

var
  ConfigPage: TInputQueryWizardPage;
  DetectedInstallMode: Integer;
  InstallModeReason: String;

{ Classify the selected install directory immediately before setup changes
  anything. No identity means the normal enrollment path (and a new token) is
  required. An identity is upgraded only with its matching usable, token-free
  config; inconsistent state is blocked and left untouched. }
procedure DetectInstallMode;
var
  ConfigPath, IdentityPath: String;
begin
  ConfigPath := ExpandConstant('{app}\config.json');
  IdentityPath := ExpandConstant('{app}\identity.json');
  InstallModeReason := '';

  if not FileExists(IdentityPath) then
  begin
    DetectedInstallMode := InstallModeFresh;
    Log('NodeLink installer mode: enrollment (no existing identity)');
    exit;
  end;

  if not FileExists(ConfigPath) then
  begin
    DetectedInstallMode := InstallModeBlocked;
    InstallModeReason :=
      'An existing identity.json was found, but config.json is missing. ' +
      'Setup will not modify this installation. Restore the matching ' +
      'token-free config or deliberately ' +
      'uninstall the existing agent before enrolling again.';
    Log('NodeLink installer mode: blocked (existing config is missing)');
    exit;
  end;

  DetectedInstallMode := InstallModeUpgrade;
  Log('NodeLink installer mode: upgrade (existing enrollment will be preserved)');
end;

{ Use the new release binary to parse the existing config and protected
  identity envelope before ssInstall touches the service or application files.
  The check is read-only and never logs their contents. DPAPI payload decryption
  remains the service identity's responsibility at startup. }
function ValidateExistingEnrollment: Boolean;
var
  Exe, Params: String;
  ResultCode: Integer;
begin
  Result := False;
  ExtractTemporaryFile('{#UpgradeValidatorExe}');
  Exe := ExpandConstant('{tmp}\{#UpgradeValidatorExe}');
  Params := 'validate-upgrade -config "' +
    ExpandConstant('{app}\config.json') + '"';
  if not Exec(Exe, Params, ExpandConstant('{tmp}'), SW_HIDE,
      ewWaitUntilTerminated, ResultCode) then
  begin
    Log('Upgrade preflight failed: could not run the release agent validator');
    exit;
  end;
  if ResultCode <> 0 then
  begin
    Log('Upgrade preflight rejected the existing enrollment state (exit code ' +
      IntToStr(ResultCode) + ')');
    exit;
  end;
  Log('Upgrade preflight accepted the existing token-free config and protected identity');
  Result := True;
end;

procedure InitializeWizard;
begin
  ConfigPage := CreateInputQueryPage(wpSelectDir,
    'Agent enrollment',
    'Connect this agent to NodeLink',
    'Enter the one-time enrollment token your administrator gave you, then ' +
    'click Next. The production server is configured automatically.');
  ConfigPage.Add('Enrollment token:', False);
end;

{ SidecarToken reads the token from a personalized-download sidecar placed next
  to Setup.exe. Only the first line is used, trimmed; a missing file yields an
  empty string. The token is never echoed to the UI or the log. }
function SidecarToken: String;
var
  Path: String;
  Raw: AnsiString;
begin
  Result := '';
  Path := ExpandConstant('{src}\{#SidecarTokenFile}');
  if FileExists(Path) and LoadStringFromFile(Path, Raw) then
  begin
    Result := String(Raw);
    { Keep only the first line, then trim surrounding whitespace/newlines. }
    if Pos(#10, Result) > 0 then
      Result := Copy(Result, 1, Pos(#10, Result) - 1);
    Result := Trim(Result);
  end;
end;

{ Token precedence: explicit /TOKEN= arg, then the personalized sidecar, then
  the interactive wizard input. This keeps a dashboard-generated download fully
  zero-touch while a plain stock installer stays simple and interactive. }
function EnrollToken: String;
begin
  Result := Trim(ExpandConstant('{param:Token|}'));
  if Result = '' then
    Result := SidecarToken;
  if Result = '' then
    Result := Trim(ConfigPage.Values[0]);
end;

{ Skip the enrollment-token page entirely when a token is already supplied by a
  /TOKEN= arg or a bundled sidecar, so a personalized install shows no token
  prompt at all. The plain stock installer (no arg, no sidecar) still shows it. }
function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if PageID = ConfigPage.ID then
  begin
    DetectInstallMode;
    if DetectedInstallMode <> InstallModeFresh then
      Result := True
    else
      Result := (Trim(ExpandConstant('{param:Token|}')) <> '') or
        (SidecarToken <> '');
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Token: String;
begin
  Result := True;
  if CurPageID = ConfigPage.ID then
  begin
    Token := EnrollToken;
    if Token = '' then
    begin
      MsgBox('Please enter the enrollment token from your administrator.',
        mbError, MB_OK);
      Result := False;
      exit;
    end;
  end;
end;

{ This is the last fail-closed gate before ssInstall removes the old service
  and [Files] replaces the binary. Returning a message keeps all existing
  runtime files and service registration untouched. It also covers silent
  installs, where wizard-page validation is not invoked. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  DetectInstallMode;
  if (DetectedInstallMode = InstallModeUpgrade) and
      (not ValidateExistingEnrollment) then
  begin
    DetectedInstallMode := InstallModeBlocked;
    InstallModeReason :=
      'The existing NodeLink enrollment could not be validated for a safe ' +
      'upgrade. Setup will not remove the service or modify any installed ' +
      'files. Review the installer log, restore the valid protected identity ' +
      'and token-free config, or deliberately uninstall before enrolling again.';
  end;
  if DetectedInstallMode = InstallModeBlocked then
    Result := InstallModeReason
  else
    Result := '';
end;

{ JsonEscape escapes the characters that would break a JSON string literal.
  Backslash must be replaced first so escaped quotes are not double-escaped. }
function JsonEscape(const S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '\', '\\', True);
  StringChangeEx(Result, '"', '\"', True);
end;

{ WriteConfig writes config.json into the install dir from the wizard inputs.
  The agent's own
  `install -config` step validates it (config.Load) before the service is
  registered, so a malformed value fails loudly at install time. }
procedure WriteConfig;
var
  Path, Json, Token: String;
begin
  if DetectedInstallMode = InstallModeUpgrade then
  begin
    Log('Preserving existing token-free config.json during upgrade');
    exit;
  end;

  Token := EnrollToken;
  { In a silent/unattended install the wizard validation never runs, so guard
    the token here too rather than write a config the agent will reject. }
  if Token = '' then
    RaiseException('No enrollment token provided (pass /TOKEN= for silent install)');
  Path := ExpandConstant('{app}\config.json');
  Json :=
    '{' + #13#10 +
    '  "server_url": "{#ProductionServerURL}",' + #13#10 +
    '  "enrollment_token": "' + JsonEscape(Token) + '"' + #13#10 +
    '}' + #13#10;
  if not SaveStringToFile(Path, Json, False) then
    RaiseException('Could not write ' + Path);
end;

{ RunAgent runs an agent CLI verb, surfacing Activity on the progress page and
  failing the install with a clear message if the verb fails. }
procedure RunAgent(const Params, Activity: String);
var
  Exe: String;
  ResultCode: Integer;
begin
  Exe := ExpandConstant('{app}\rmm-agent.exe');
  WizardForm.StatusLabel.Caption := Activity + '...';
  WizardForm.StatusLabel.Update;
  if not Exec(Exe, Params, ExpandConstant('{app}'), SW_HIDE,
      ewWaitUntilTerminated, ResultCode) then
    RaiseException(Activity + ' failed: could not run ' + Exe);
  if ResultCode <> 0 then
    RaiseException(Activity + ' failed (exit code ' + IntToStr(ResultCode) +
      '). See %ProgramData%\NodeLink\logs\rmm-agent.log for details.');
end;

{ All service work happens here, NOT in [Run]: [Run] executes before
  ssPostInstall, so a [Run] entry could not see the config.json written below.
  Ordering: write config, register the service, start it — each step updating
  the visible status text.

  Note the agent's `install -config` normally copies the config next to the
  binary; since config.json is already in the install dir, passing its own path just
  validates it in place (see installConfig in service_windows.go). }
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    { Re-install/upgrade: if a previous copy is present, let the agent stop and
      deregister its own service (idempotent) so the binary is not locked while
      being overwritten. Best-effort by design — on a fresh install the exe
      does not exist yet and there is nothing to do. }
    if FileExists(ExpandConstant('{app}\rmm-agent.exe')) then
      RunAgent('uninstall', 'Removing the previous NodeLink Agent service');
  end;

  if CurStep = ssPostInstall then
  begin
    if DetectedInstallMode = InstallModeUpgrade then
    begin
      WizardForm.StatusLabel.Caption :=
        'Preserving the existing NodeLink enrollment...';
      WizardForm.StatusLabel.Update;
      Log('Upgrade: identity.json and config.json are being preserved');
    end
    else
    begin
      WizardForm.StatusLabel.Caption := 'Writing agent configuration...';
      WizardForm.StatusLabel.Update;
      WriteConfig;
    end;
    { The agent's `install` refuses to run when a NodeLinkAgent service already
      exists — e.g. one registered earlier via the CLI path from a different
      directory, which the ssInstall check above cannot see. `uninstall` is
      idempotent (no-op on a clean machine, stops + removes by service name
      otherwise), so always run it via the just-copied exe before installing. }
    RunAgent('uninstall', 'Removing any existing NodeLink Agent service');
    RunAgent('install -config "' + ExpandConstant('{app}\config.json') + '"',
      'Registering the NodeLink Agent service');
    RunAgent('start', 'Starting the NodeLink Agent service');
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
  begin
    if DetectedInstallMode = InstallModeUpgrade then
      WizardForm.FinishedLabel.Caption :=
        'Setup has finished updating NodeLink RMM Agent on your computer.' + #13#10 + #13#10 +
        'The existing enrollment and configuration were preserved. The ' +
        'updated agent is running as the Windows service "NodeLink RMM Agent".'
    else
      WizardForm.FinishedLabel.Caption :=
        'Setup has finished installing NodeLink RMM Agent on your computer.' + #13#10 + #13#10 +
        'The agent is enrolled with your NodeLink server and running as the ' +
        'Windows service "NodeLink RMM Agent".';
  end;
end;
