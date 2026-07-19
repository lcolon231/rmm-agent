; NodeLink RMM Agent — graphical Windows installer.
; SPDX-License-Identifier: AGPL-3.0-only
;
; Wraps the existing Go agent binary in an Inno Setup installer so a
; non-technical person can install the agent without touching a terminal:
; pick nothing, enter the server URL + enrollment token, watch progress, done.
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
Type: dirifempty; Name: "{app}"

[Code]
var
  ConfigPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  ConfigPage := CreateInputQueryPage(wpSelectDir,
    'Server connection',
    'How this agent reaches your NodeLink RMM server',
    'Enter the server address and the one-time enrollment token your ' +
    'administrator gave you, then click Next.');
  ConfigPage.Add('Server URL:', False);
  ConfigPage.Add('Enrollment token:', False);
  { Prefill the scheme to nudge users toward TLS. }
  ConfigPage.Values[0] := 'https://';
end;

{ ServerURL/Token prefer the command-line parameters (/SERVERURL= /TOKEN=),
  falling back to the wizard inputs. This makes the installer scriptable for
  unattended/CI deployment (`/VERYSILENT /SERVERURL=... /TOKEN=...`) while the
  interactive wizard still works when no parameters are passed. }
function ServerURL: String;
begin
  Result := Trim(ExpandConstant('{param:ServerURL|}'));
  if Result = '' then
    Result := Trim(ConfigPage.Values[0]);
end;

function EnrollToken: String;
begin
  Result := Trim(ExpandConstant('{param:Token|}'));
  if Result = '' then
    Result := Trim(ConfigPage.Values[1]);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  URL, Token: String;
begin
  Result := True;
  if CurPageID = ConfigPage.ID then
  begin
    URL := ServerURL;
    Token := EnrollToken;
    { The bare prefill counts as empty. }
    if (URL = '') or (URL = 'https://') then
    begin
      MsgBox('Please enter the server URL, e.g. https://rmm.example.com',
        mbError, MB_OK);
      Result := False;
      exit;
    end;
    if Token = '' then
    begin
      MsgBox('Please enter the enrollment token from your administrator.',
        mbError, MB_OK);
      Result := False;
      exit;
    end;
  end;
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
  Path, Json, URL, Token: String;
begin
  URL := ServerURL;
  Token := EnrollToken;
  { In a silent/unattended install the wizard validation never runs, so guard
    the values here too rather than write a config the agent will reject. }
  if (URL = '') or (URL = 'https://') then
    RaiseException('No server URL provided (pass /SERVERURL= for silent install)');
  if Token = '' then
    RaiseException('No enrollment token provided (pass /TOKEN= for silent install)');
  Path := ExpandConstant('{app}\config.json');
  Json :=
    '{' + #13#10 +
    '  "server_url": "' + JsonEscape(URL) + '",' + #13#10 +
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
    WizardForm.StatusLabel.Caption := 'Writing agent configuration...';
    WizardForm.StatusLabel.Update;
    WriteConfig;
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
