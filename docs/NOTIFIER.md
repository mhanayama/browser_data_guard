# Tray notifications and credential inventory

For the installed ETW host service, the single-row page navigation, persisted
history loading, `.log` exports, removal dialogs and Windows Application events,
see [HOST_MONITOR.md](HOST_MONITOR.md). These additions observe real paths but
do not enable the lab driver's enforcement on them.

The .NET 9 Windows Forms notifier runs as the interactive user, without elevation.
It provides a resident notification-area icon, dashboard, bounded 200-event
history, and one reused modeless alert window for denied access records.
Closing the dashboard hides it; use the tray menu to exit. It does not install
itself at login. The PowerShell console viewer remains available separately.

## Build and run

Requires .NET SDK 9 with Windows Desktop targeting/runtime packs. No third-party
NuGet packages or API calls are used.

```powershell
.\scripts\Build-Notifier.ps1
.\scripts\Start-BdgTray.ps1 -Log C:\path\to\collector-events.jsonl
# Game / presentation mode: no dashboard or automatic alert/balloon popups
.\scripts\Start-BdgTray.ps1 -Background -NoPopups
# Explicit visual demonstration, not a detected access
.\scripts\Start-BdgTray.ps1 -TestAlert
```

The development launcher stores its state under `out/tray-state`. The default
log is `out/tray-state/events.jsonl`; point `-Log` at the collector's actual log.
Starting the notifier does not start the collector, load the driver, or enable
any protection. A second instance in the user session exits. The CLI also
accepts `--state-dir`, `--log`, `--background`, `--no-popups`, `--test-alert`,
and `--run-seconds N` (diagnostic timed shutdown).

## Actual protection state

**All browser and credential candidates are currently unprotected.** Driver ABI
v1 still accepts only one synthetic `BDG-Lab\Protected` root and one exact process
grant. The inventory is not sent to the driver. No FileSystemWatcher is used
to suggest that file reads have been detected or blocked.

The collector emits a synthetic-mode heartbeat every two seconds, after a
successful kernel status/event query. The notifier requires a heartbeat less
than eight seconds old and a live PID with matching process creation FILETIME
to show a lab collector connection. Old `status` records cannot do this. Log
disconnect/rotation, explicit stop, stale heartbeat, inaccessible process, or
PID reuse clear connection health. `realDataProtected` stays false even when
lab telemetry is live. Abrupt collector exit is handled by process/liveness
checks; the collector's port teardown still revokes the lab trust grant.

JSONL is a notification transport, not authenticated evidence of protection.
Someone able to modify the log can inject notifications. Production needs an
ACL-protected, read-only, owner-scoped service IPC channel. Kernel decisions
remain independent of this UI. Audit-loss and malformed-record counts are
visible. The tailer skips pre-start history, bounds records to 64 KiB and reads
at most 128 KiB per timer tick; it handles partial UTF-8, truncation and identity
changes. In-place truncate-and-regrow between polls can evade truncation
detection; rotate to a new file identity. History is memory-only.

Alerts show time, process/PID, executable, application/category and target.
Name-query failure events still alert when no target name is available. Event
flags warn of truncated/unavailable paths. Multiple detections reuse one
window, showing the latest event and notification count. `--no-popups` keeps
history and counts but suppresses automatic alert windows and balloons.
The explicitly requested display test is prominently labelled as a test.

## Discovery scope

Discovery is read-only and runs in the current user's context, initially and
every 60 seconds, or on demand. Only Firefox `profiles.ini` / `installs.ini`
location manifests are read as content (bounded size). Cookie databases,
LevelDB files, Chromium `Local State`, authentication files and private keys
are never opened for their contents. No decrypt/hash/export of secrets occurs.
Existence checks do not establish that a file actually contains credentials;
“unconfirmed” can also mean inaccessible. Inventory contains sensitive path
metadata: it stays local and should not be uploaded casually.

| Type | Candidate discovery | Limits |
| --- | --- | --- |
| Chrome / Edge | Standard user-data roots; direct child profiles with Preferences, Cookie or Local Storage evidence | Other channels/custom user-data roots need manual registration; empty profiles without evidence may be missed |
| Chromium storage | `Network/Cookies`, legacy `Cookies`, SQLite `-wal/-shm/-journal`, `Local Storage/leveldb`, root `Local State` | Includes not-yet-created companions; does not read the encrypted material |
| Firefox | Relative/absolute profile paths from INI plus `Profiles` directories; Cookie/legacy storage SQLite companions, `storage/ls-archive.sqlite`, per-origin `storage/default/*/ls` | Does not label IndexedDB or all origin storage as Local Storage |
| ChatGPT / Codex embedded browser | Matching app folders under Local/Roaming AppData and matching MSIX package data folders; Chromium/Electron partition layout evidence | App-specific, bounded heuristic (depth 8, 2048 directories per app root); no claim to cover every embedded engine/application |
| Codex authentication | `$CODEX_HOME/auth.json`, otherwise `%USERPROFILE%\.codex\auth.json`; additional recognized filenames only when present | Candidate path only; credential-store mode has no corresponding auth file |
| SSH files | Direct `.ssh` filenames beginning `id_`, or ending `.pem` / `.ppk`; `.pub` excluded | Filename candidates, not content verification; arbitrary names/other paths must be registered manually; no SSH config parsing |
| API/client authentication | Existing AWS credentials / SSO and CLI caches; known Azure token cache files, Google ADC, npm/Python/Docker/Git credential config paths | Version/layout dependent; configurations may contain no secret; no parsing of their contents |
| User-selected targets | File or folder picker; up to 200 local absolute paths persisted in `custom-targets.json` | Whole selected folder subtree is a candidate; no policy activation or application authorization |

Each directory listing is bounded to 512 entries. Reparse points are skipped;
UNC/device/alternate-stream paths are rejected for manual registration. This
is defensive discovery, not race-proof canonicalization for enforcement.
No recursive drive scan or environment-variable-value collection occurs.
`AWS_SHARED_CREDENTIALS_FILE` and `GOOGLE_APPLICATION_CREDENTIALS` are used only
as configured file paths. Workspaces' `.env`, unusual key filenames, custom
embedded browser data, and other clients can be manually registered. Automatic
discovery does not cover WSL/container/remote filesystems.

Windows Credential Manager, DPAPI/key-store access, SSH Agent signing, hardware
keys, environment values and process memory require separate broker/process
controls. A file filter does not prevent an already authorized app or an
injected process from using a token/key it already holds. Generic trust for
`ChatGPT.exe`, `codex.exe`, `ssh.exe`, `node.exe`, PowerShell or an editor is not
acceptable: interpreter/extension hosts can execute unrelated code.

Before enabling these targets, implement immutable multi-resource snapshots
with owner SID, resource category and file identity, process-creation/image
binding and scope-specific grants. Exercise browser subprocesses, app updates,
SQLite/LevelDB recovery, authentication refresh/atomic replacement, SSH key
use and rotation, legitimate tools, and unauthorized probes in a VM. Preserve
the existing handles/mappings/aliases limitations until actually resolved.
Production driver signing and host load support remain separate prerequisites.

## Command-only validation

```powershell
.\scripts\Build-Notifier.ps1                 # 49 core/discovery/history tests
.\tests\Invoke-TraySmoke.ps1                 # no dashboard, popups disabled
dotnet .\out\notifier\Release\Bdg.Tray.dll --inventory C:\absolute\inventory.json
```

The smoke test runs the real resident UI event loop for ten seconds in
background mode, injects one **telemetry fixture** into a private test log,
checks processing/history/unprotected status, then requires clean timed exit.
It neither loads a driver nor claims an actual file denial. It writes
`out/testing/tray-smoke-result.json`. The notifier writes small `startup.txt`
and `runtime.json` diagnostic files in its state directory, containing stages,
counts and health, not secret file contents.

After the user authorized GUI testing, interactive validation on 2026-11-05
confirmed readable candidate/status views, the explicitly labelled display-test
alert, its close button, the corresponding test-labelled history row, and the
scope/diagnostics tab. Closing the dashboard with its title-bar close button
removed the visible window while the same resident process continued its event
loop. The notifier was left resident with automatic alerts enabled. The check
found 143 candidate paths (76 existence-confirmed); these counts are metadata,
not a credential count or protection coverage. No real denial was generated,
the lab service was disconnected, and real-data protection stayed false.

Host metadata discovery on 2026-11-05 found standard Chrome, Edge and Firefox
layouts and a packaged Codex embedded-browser layout. A separate ChatGPT layout
was not found by the known-folder heuristic. This is not proof of absence of
ChatGPT or credentials, and is not an enforcement test. No BDG host driver was
loaded; Secure Boot and HVCI remain enabled.

References: [Codex authentication storage](https://learn.chatgpt.com/docs/auth),
[WebView2 user-data folders](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder),
[Windows OpenSSH key management](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement),
[Windows Forms NotifyIcon](https://learn.microsoft.com/en-us/dotnet/api/system.windows.forms.notifyicon?view=windowsdesktop-9.0).
