# Browser Data Guard (BDG)

A Windows 11 defensive security experiment that gates file opens before access.
This repository contains Phase 1 architecture and a Phase 2 **synthetic-directory
PoC**. It does not currently protect real Chrome, Edge, or Firefox profiles.

The WDK minifilter denies unauthorized content opens with `STATUS_ACCESS_DENIED`.
A C++20 service verifies a specifically configured process using its image path,
owner SID, SHA-256 pin and Authenticode, then passes an open process handle to the
driver. The driver retains the process object, preventing PID-reuse inheritance.
Decisions are local to the kernel; event collection never sits in the access path.
A resident tray notifier displays decisions and process/target details, with
read-only browser and credential-location discovery. Discovery does not enable
protection for those locations.
The host can now run a separate **ETW observation-only service**, without loading
the lab driver. See [host monitor, history and Windows logs](docs/HOST_MONITOR.md).

**Status, 2026-11-05:** WDK 26100.6584, VS 2022 WDK integration and x64/x86
Spectre libraries are installed. The x64 Debug driver build passes with zero
warnings/errors; Release builds and recommended-rule static analysis also pass.
The local test suite now includes native Win32 probes (3 suites, 92 assertions).
A dedicated Windows 11 evaluation VM successfully ran 40 checks under Driver
Verifier, plus clean unload/reload and existing-handle/mapping limitation checks.
VM-only test signing and installation were exercised. Build outputs remain
unsigned; the separate VM package uses a VM-only test certificate. No BDG driver
was installed/loaded on the development host. Read-only profile/credential path
discovery was subsequently added; real databases, auth files and keys are not
read or modified. See [VM evidence and limits](docs/VM_TEST_REPORT.md) and
[tray notifier and credential scope](docs/NOTIFIER.md).

## Tray notifier and credential candidates

```powershell
.\scripts\Build-Notifier.ps1
.\scripts\Start-BdgTray.ps1
# Silent background mode while gaming:
.\scripts\Start-BdgTray.ps1 -Background -NoPopups
```

Requires .NET 9 Windows Desktop. The tray app provides a dashboard, denial alert
window, bounded history and connection/loss status. It discovers Chrome, Edge,
Firefox, known ChatGPT/Codex embedded-browser layouts, Codex auth-file paths,
SSH key filenames and known API/client credential files without reading secrets.
Files/folders can also be registered manually. **These candidates remain
unprotected:** the driver still supports only the lab root. An explicit display
test is distinct from detection. See [usage, scope and tests](docs/NOTIFIER.md).

## Build user-mode components

```powershell
.\scripts\Get-Environment.ps1
.\scripts\Build.ps1 -Configuration Debug
```

This builds the service, access probe and tests using CMake's Visual Studio
generator/MSBuild. It does not build, install, or load the driver. Driver build:
`scripts/Build.ps1 -Driver`, requiring matching SDK/WDK files and VS integration.
See [development and VM instructions](docs/DEVELOPMENT.md) before packaging.

## Repository

| Location | Contents |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Design, APIs and deferred browser integration |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Adversary, exclusions and trust assumptions |
| [docs/SECURITY_BOUNDARIES.md](docs/SECURITY_BOUNDARIES.md) | Guarantees versus bypasses and stability risks |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Build, VM installation, signing, removal and recovery |
| [docs/VALIDATION.md](docs/VALIDATION.md) | Environment, test evidence, coverage and next steps |
| `driver/` | WDK C source, x64 MSBuild project, INF template |
| `service/` | C++20 console/SCM collector and process verification |
| `notifier/` | .NET tray dashboard/alerts/discovery and PowerShell console viewer |
| `shared/` | Versioned wire ABI and policy helpers |
| `tests/` | Policy/identity tests, native access probes and VM test suite |
| `scripts/` | Environment/build and explicit VM preparation utilities |

## Limits that matter

The PoC uses one immutable, configurable NTFS lab root and one process grant.
It does not revoke existing handles or mappings. Outside hard links, namespace
races, rename through existing handles, and loaded-image verification races
remain gaps. A service disconnect removes the grant but cannot invalidate old
handles. Loading/attachment failure and driver unload mean no protection.

Read-only browser/credential discovery is implemented. Policy activation,
profile-scoped ownership grants, automatic browser updates and backup
exceptions remain Phase 3 work. The VM tests use
browser-shaped **text fixtures**, not SQLite databases or genuine browsers.
BDG does not claim complete protection against browser session theft.
