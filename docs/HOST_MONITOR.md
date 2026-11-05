# Host observation service (ETW, no blocking)

`BdgMonitor` is a Windows service which consumes the manifest-based
`Microsoft-Windows-Kernel-File` ETW provider. It observes selected real browser,
embedded-browser and credential-file paths without loading BDG's minifilter.
**It does not block access, infer malicious intent, or establish operation success.**
The existing minifilter and lab collector remain a separate synthetic-only mode.

On 2026-11-05 the host service was installed and started, with 140 snapshot rules.
Actual opens by `ChatGPT.exe` in the Codex embedded-browser data and by
`msedge.exe` in Edge data were recorded. A dummy-file integration test verified
open/read/write, requester PID, subtree-boundary exclusion and clean exit, with
zero reported event loss/decode errors. These are observation tests, not denial
tests. Secure Boot/HVCI were left enabled and no BDG host driver was loaded.

## Build, configure and run

```powershell
.\scripts\Build.ps1 -Configuration Release
.\scripts\Build-Notifier.ps1
# Run discovery as the interactive user; writes path metadata only.
dotnet .\out\notifier\Release\Bdg.Tray.dll --background --state-dir C:\dev\browser_data_guard\out\tray-state --export-monitor-policy C:\dev\browser_data_guard\out\testing\host-observe-policy.tsv
# In an elevated PowerShell, supply the intended interactive user's SID:
.\scripts\Install-ObserveService.ps1 -OwnerSid S-1-5-21-...
# Return to the ordinary user:
.\scripts\Start-BdgTray.ps1 -Background -Log C:\ProgramData\BrowserDataGuard\logs\events.jsonl
```

The installer runs the real-I/O fixture test before installation, then copies
the service executable and snapshot to `C:\ProgramData\BrowserDataGuard`.
SYSTEM/Administrators own and can write the installation; the selected user has
read/execute access, including logs. Reparse installations and unexpected service
commands/event sources are rejected. The source workspace is development input,
not the privileged service executable location. The installed service uses
LocalSystem for ETW and starts manually. It remains running until stopped or
rebooted; it is not configured to start automatically at boot.

The snapshot is immutable while running. UI add/remove actions modify candidate
discovery, not the installed monitor rules. To change those rules, export again
as the user and rerun the elevated installer; this deliberately restarts the
observer with a short observation gap. The driver receives none of these rules.
Changing Windows boot/security settings is not part of installation.

```powershell
Get-Service BdgMonitor
# Elevated, when observation should end:
Stop-Service BdgMonitor
# Optional removal of the service registration, after stopping it:
sc.exe delete BdgMonitor
```

Removing the registration does not remove binaries, logs or the event-message
source: keeping the executable allows older Windows event messages to remain
readable. No automatic log clearing or recursive installation removal is done.

## Recorded data and bounds

Only matching paths are persisted. ETW metadata for system-wide file I/O passes
through the consumer to correlate selected file objects/keys; unrelated paths
are not written. Neither file contents, cookie values, keys nor call stacks are
collected. Only create/open requests and correlated read/write requests are
reported, not arbitrary filesystem changes. `open` can be a metadata-only
request, including the tray's own existence checks; it does not prove content
was read. ETW completion outcomes are not collected.

Rules use DOS-to-device name conversion and component boundaries, including
subtree roots/children and ADS. They are path matches, not alias-proof object
protection. Correlation can miss old handles, mappings/paging, alternate names,
renames, dropped events and changes after the snapshot. Requester attribution
uses a best-effort live issuing-thread lookup, with process birth-time checks;
an exited/inaccessible requester is unknown. This is not authorization or a
complete forensic attribution guarantee. A reused thread in an older process
is an unresolved attribution limitation.

Per-file/thread/operation requests are aggregated over about two seconds, with
counts and requested byte totals. File-object and file-key maps are bounded at
16384 entries each, aggregates at 4096; pressure increments a loss indicator.
ETW buffers are bounded (64 KiB, at most 64 buffers). `unmappedReadsWrites`
includes intentionally untracked/non-target I/O as well as unresolvable paths;
it is not a count of missed accesses to known target files. Session/consumer
failure ends the collector, rather than emitting a healthy heartbeat. Shutdown
stops only its uniquely named private ETW session.

The JSONL log rotates at 8 MiB into one `.1` file (roughly 16 MiB total, plus a
bounded final batch). Heartbeat counters expose received/matched/undecodable/
lost data. Disk/Windows-event-log write failure stops the collector. The tray
requires a fresh heartbeat and matching live process birth; a background WMI
metadata query handles SYSTEM processes whose ACL denies native queries. No
pending WMI operation blocks the UI; old verification expires.

## Access history, exports and removal dialogs

The tray opens on a separate **履歴一覧** page. A single navigation row switches
between 対象一覧 / 履歴一覧 / 状態; there is no duplicate tab strip.
It imports up to 200 recent access entries from bounded tails (1 MiB each) of the
current service log and its `.1` rotation, then appends live records. Imported
history never replays denial popups; overlapping live records are deduplicated.
Observe,
deny, allow and explicit display-test entries are distinguishable. Double-click
a row for full process/PID, target, operation, count and diagnostics. Observe
records do not trigger denial popups. The persistent service/Windows logs are
separate from this bounded in-memory view.

`履歴を .log に保存` exports the currently held history through a Save dialog,
as UTF-8 JSON Lines. It includes an export header and escaped path/process
metadata, so control characters cannot create forged entries. The save dialog
confirms overwrites; cancellation writes nothing. It does not export secret
contents or the complete historical service log.

`手動登録を解除` asks Yes/No (default No) for a manual candidate. Standard
discovered candidates show `標準項目は削除できません` with OK. Actual target
files are never deleted. A manual duplicate does not make a standard target
removable. Save failure restores the in-memory registration list.

## Windows Application log

Source: **BrowserDataGuard**. Message resources are embedded in the installed
service executable and registered for Event Viewer; messages are formatted,
not just raw insertion strings. The service writes these events in addition to
JSONL. No global Windows audit policy, Security log or SACL is changed.

| ID | Level | Meaning |
| --- | --- | --- |
| 1000 | Information | Observed ETW request(s), no blocking/outcome determination |
| 1001 | Warning | Actual lab minifilter policy denial |
| 1002 | Information | Actual lab policy allowance; filesystem can still deny |
| 1003 | Warning | Audit/correlation loss reported |
| 1004 | Information | Collector start/stop and mode |
| 1005 | Error | SCM collector failure |

No fake deny/allow Windows events were generated to suggest real browser
protection. Their six message resources were verified offline by the
`windows-event-format` CTest. Actual event IDs 1000/1004 and message formatting
were read back from the host Application log. Windows log retention follows
the existing Application log policy; the installer does not expand/clear it.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='BrowserDataGuard'} -MaxEvents 30
```

References: [ETW session configuration](https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session),
[file I/O event semantics](https://learn.microsoft.com/windows/win32/etw/fileio),
[Windows event sources](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-sources).
