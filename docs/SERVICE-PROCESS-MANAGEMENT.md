# Typed Windows service and process management

Issue #57 adds four typed Windows commands: `list_services`, `control_service`, `list_processes`, and `terminate_process`. They use the existing signed `command-v3` transport and durable result path; they never accept script text or fall back to shell execution.

## Contract

### `list_services` and `list_processes`

`list_services` and `list_processes` are read-only, operator-level discovery operations. They accept an empty JSON payload `{}`. The agent returns bounded JSON evidence in stdout with standard listing fields:

```json
{
  "status": "ok",
  "services": [
    {
      "name": "Spooler",
      "display_name": "Print Spooler",
      "state": "Running",
      "start_mode": "Auto",
      "account": "LocalSystem"
    }
  ],
  "count": 1
}
```

```json
{
  "status": "ok",
  "processes": [
    {
      "pid": 1234,
      "name": "explorer.exe"
    }
  ],
  "count": 1
}
```

Results are hard-bounded to `MaxServices = 1000` and `MaxProcesses = 2000` to prevent an unbounded result from exceeding payload limits. If truncated, the JSON response includes `"truncated": true`.

### `control_service`

`control_service` is an administrator-only service mutation command. It accepts:

```json
{
  "name": "Spooler",
  "action": "restart",
  "confirm": true,
  "reason": "Approved ticket #12345 for service recovery"
}
```

- `name`: 1–256 characters matching `^[A-Za-z0-9_.\- ]{1,256}$`.
- `action`: exactly `"start"`, `"stop"`, or `"restart"`.
- `confirm`: must be `true`.
- `reason`: 10–512 printable UTF-8 bytes without control characters.

### `terminate_process`

`terminate_process` is an administrator-only process termination command. It accepts:

```json
{
  "pid": 1234,
  "expected_name": "notepad.exe",
  "confirm": true,
  "reason": "Approved ticket #12346 for hung process termination"
}
```

- `pid`: positive integer (PIDs 0 and 4 are always protected).
- `expected_name`: optional string (up to 260 characters). If supplied, the agent resolves the live image name of the target process and fails closed if it does not match (preventing accidental termination if a PID was recycled).
- `confirm`: must be `true`.
- `reason`: 10–512 printable UTF-8 bytes without control characters.

### Result Statuses

The command output status field contains one of:

- `ok`: operation completed successfully.
- `invalid`: the typed payload failed validation (bad name pattern, invalid action, `confirm != true`, short/control-char reason, or unexpected fields).
- `protected`: the target service or process is in the protected denylist and cannot be controlled/terminated.
- `not_found`: the target service or process ID does not exist on the endpoint.
- `name_mismatch`: for `terminate_process`, the live process image name did not match the expected name.
- `unavailable`: the endpoint encountered an error querying CIM/WMI or Windows APIs.
- `unsupported`: the operation is not supported on the agent platform.
- `failed`: Windows received a valid request but the platform action failed (e.g. access denied).

## Protected Target Denylists

To protect endpoint stability, security posture, and agent communication, the server and agent enforce identical, case-insensitive denylists.

### Protected Services (`PROTECTED_SERVICES`)

`nodelinkagent`, `windefend`, `mpssvc`, `eventlog`, `rpcss`, `dcomlaunch`, `rpceptmapper`, `winmgmt`, `lsm`, `dnscache`, `dhcp`, `bfe`, `gpsvc`, `netlogon`, `samss`, `cryptsvc`, `schedule`, `profsvc`, `plugplay`, `power`, `nsi`.

### Protected Processes (`PROTECTED_PROCESSES`)

PIDs `0` (System Idle) and `4` (System), the agent's own PID (`selfPID`), plus image names:
`system`, `idle`, `smss.exe`, `csrss.exe`, `wininit.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`, `lsm.exe`, `svchost.exe`, `nodelinkagent.exe`.

The server validates denylists during payload parsing and fails closed (ValueError 422). The agent re-validates authoritatively at the endpoint before executing.

## Authorization & Capabilities

- `list_services` and `list_processes` require an `operator` or `admin` role and the `service-process-v1` capability.
- `control_service` and `terminate_process` require an `admin` role and the `service-process-v1` capability.
- If an agent does not advertise `service-process-v1`, the server rejects dispatch with HTTP 409 (`agent_capability_unsupported`).
- If an operator lacks the required role, the server records `command.authorization_denied` with reason `administrator_role_required` or `operator_role_insufficient` and returns HTTP 403 (`service_process_not_authorized`).

## Audit Logging

No free-text operational reasons are stored in plain text.
- `service_control.dispatched`: records `action`, `service`, `reason_sha256`, and `reason_bytes`.
- `process_terminate.dispatched`: records `pid`, `expected_name_present`, `reason_sha256`, and `reason_bytes`.

## No Schema Change

This feature rides the existing `Command` model and `command-v3` signed envelope transport. No Alembic database migration is required. Dashboard UI is deferred matching the scope decisions used for issues #55 and #56.
