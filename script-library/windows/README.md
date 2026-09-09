# Windows library scripts

These PowerShell 5.1-compatible scripts are ready to add to NodeLink's script
library. Adding these files to the repository does not register or execute them
on endpoints. They use the library's injected `$NL_PARAM_*` variables and return
JSON on stdout. Do not add a `param()` block: the library prepends assignments.

| Script | Behavior | Parameters |
| --- | --- | --- |
| `health-check.ps1` | Read-only OS, uptime, memory, fixed disks, Defender, two reboot indicators, and up to 50 stopped automatic services | None |
| `disk-cleanup.ps1` | Preview/delete old files directly in `%windir%\Temp` | `Preview`: boolean, default `true`; `MinimumAgeDays`: number, whole days 1–365, default `7` |
| `service-management.ps1` | Status/start/stop/restart one service | `ServiceName`: required string, 1–256 characters; `Action`: choice `status`, `start`, `stop`, `restart`, default `status` |

## Add to the library

1. Open **Scripts → New script** in the dashboard.
2. Use the name, description, and tags from `catalog.json`. Select **PowerShell**
   and **Windows**, and paste the corresponding `.ps1` file into Script content.
3. Add the parameters from the table above, including defaults, choices, and
   bounds. The exact parameter keys are case-sensitive within the catalog.
4. Save and complete the library's version review before running on an endpoint.

For API workflows, build a single `ScriptCreate` request body from the catalog
with this PowerShell snippet, run from the repository root:

```powershell
$entry = @(Get-Content script-library/windows/catalog.json -Raw | ConvertFrom-Json)[0]
$sourceFile = Join-Path 'script-library/windows' $entry.file
$entry.PSObject.Properties.Remove('file')
$entry | Add-Member -NotePropertyName content -NotePropertyValue (Get-Content -LiteralPath $sourceFile -Raw)
$entry | ConvertTo-Json -Depth 10
```

Use index `0`, `1`, or `2` for the desired script. The output is a request body
for the existing `POST /script-library` API route (under the server's API prefix).
Creation does not approve or execute a version.

## Running

- **Health:** section `Status=ok` means collection succeeded. Assess the values
  separately. Stopped automatic services can be normal (for example, triggered
  services); the reboot checks are indicators, not an exhaustive detection.
  Missing Defender/CIM access produces an `unavailable` section.
- **Cleanup:** run with `Preview=true` first, then set it to `false` to delete.
  Only top-level old files are eligible. User profiles, downloads, recycle bins,
  temp subdirectories, and Windows Update caches are outside its scope. Locked
  files are counted as failures; partial deletion is reported before the script
  fails. Deleted bytes are logical file sizes, not guaranteed recovered disk space.
- **Services:** use the service name (for example `Spooler`), not its display
  name. Status is the default. Start/stop/restart require appropriate Windows
  rights and report errors for missing services, dependency constraints, or
  failure to reach the requested state. Service changes may interrupt applications.

Use the endpoint agent's normal command timeout (allow at least 60 seconds for
health collection). Running cleanup or service changes generally requires an
elevated account. These scripts do not elevate themselves.

## Verification

Run `powershell.exe -NoProfile -File script-library/windows/tests.ps1` from the
repository root. Tests use a unique temporary directory and mocked services;
they do not change installed services or clean the actual Windows Temp directory.
