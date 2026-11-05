# Development report — 2026-11-05 (Asia/Tokyo)

## Files and architecture

The repository separates `driver`, `service`, `notifier`, `shared`, `tests` and
`scripts`. README and the architecture, threat model, security boundaries and
development documents explain the implementation and VM lifecycle. CMake builds
the user-mode components; a standalone WDK MSBuild project builds the minifilter.

Key decisions: immutable synthetic root; pre-create denial; one referenced process
object rather than PID trust; privileged versioned Filter Manager port; no
per-access service round trip; bounded audit with explicit loss; deny on relevant
name lookup failure; service failure revokes grants while retaining the root.
Phase 3 browser discovery and fine-grained browser ownership are **not implemented**.

## Environment and executed checks

| Item | Evidence/status |
| --- | --- |
| OS reported by runtime | 10.0.26300.0, x64 build environment |
| Visual Studio | Community 2022 17.14.37827.9 |
| Compiler / MSBuild | MSVC 19.44.35229 / MSBuild 17.14.60 |
| Windows SDK | 10.0.22621.0 and 10.0.26100.0 present |
| WDK | 26100.6584 installed; kernel headers, x64 FltMgr.lib and VS toolset present |
| VS components | Windows Driver Kit integration and latest v143 x64/x86 Spectre libraries installed |
| User-mode builds | Debug and Release, MSBuild, `/W4 /WX` |
| CTest | 3 suites: 55 policy, 9 identity and 28 native-probe assertions |
| PowerShell syntax / project XML | Parsed successfully |
| Driver build preflight | Validates matching SDK/WDK files; initially rejected absent/partial setup |
| Driver x64 Debug compilation/link | Passed, `/W4 /WX`, zero warnings and errors |
| Driver static analysis | Minimum and recommended rules passed; SAL queue-lock contracts added |
| INF validation | Generated lint-only template copy passed InfVerif; no installable package/signing claim |
| VM signing/install/load/unload | Exercised in the dedicated Windows 11 evaluation VM |
| VM access suites | Baseline 37/37; extended Driver Verifier run 40/40 |
| VM removal / cleanup | Package and service absent after guest reboot; Verifier reset; VM Off |
| Existing handle/mapping/outside hard link | Known gaps confirmed in the VM |
| Real-browser validation | Not run; no real profiles inspected or modified |

The policy suite checks all sensitive access bits, zero-rights destructive
dispositions, metadata-only access, backup intent, path boundaries/streams,
strict lab-root validation and malformed wire commands. The identity suite checks
path/SID/hash rejection, successful explicit unsigned-lab verification using an
independent hash, default signature rejection, JSON escaping and timestamps.
These tests do not establish kernel correctness or browser compatibility.

Full VM results and caveats are recorded in [VM_TEST_REPORT.md](VM_TEST_REPORT.md).
The extended run included 96 denied reads with the collector stopped; audit loss
rose from 0 to 33, was reported on reconnect, and never relaxed denial. Normal
and Verifier unload/reload checks succeeded. Package-removal cleanup is recorded
separately from access enforcement and must not be inferred from an access pass.

## WDK setup and compile fixes

Microsoft's VS 2022-compatible WDK 26100.6584 installer was downloaded from the
official supported-version table and its Authenticode signature verified as
Microsoft Corporation before execution. Installer SHA-256:
`ED82C46BD98E0F1D07FD6E5075900E42AEDC3FA5E68C06A8764B3DC5303CFF1B`.
The VS component installer and WDK installer both returned 0; neither restarted
Windows. No test-signing setting, certificate trust or BDG driver service was
created, and no BDG driver was loaded.

The first real kernel compile found that the WDK headers do not expose the
user-mode `PROCESS_QUERY_LIMITED_INFORMATION` macro. The shared interface now
names its documented access-mask value, with an SDK-side static assertion to
prevent divergence. Handle type and UserMode access validation are retained.
Build preflight now rejects partial installations, selects matching SDK/WDK
versions, and disables reusable build workers. Environment inventory excludes
non-version directories such as `Include/wdf`.

The unsigned build artifact is `out/driver/Debug/BdgDriver.sys`. Static analysis
outputs are under `out/obj/driver/Debug`; local CTest evidence is under
`out/user/Testing/Temporary`. These generated files are ignored by Git.

## Runtime coverage to execute in a disposable VM

| Requirement | Harness/procedure | Status |
| --- | --- | --- |
| Designated process access | Gated native helper + pinned process handle | Passed in VM |
| Unauthorized read / copy / new mapping | Native Win32 probes, exact access-denied exit | Passed in VM |
| Multiple profiles / WAL / journals / Local Storage | Browser-shaped text fixtures | Passed; genuine databases deferred |
| Concurrent access | Independent simultaneous probe processes | Passed in VM |
| Same executable, different process | Unregistered helper instance must fail | Passed in VM |
| Renames | New DELETE-open denial automated; earlier-handle/ancestor cases manual | New-open denial passed; comprehensive namespace tests deferred |
| Hard-linked paths | Outside link read explicitly marked known gap | Bypass confirmed |
| Existing handles / mappings | Gated hold-read/hold-map before load | Bypasses confirmed |
| Service restart/failure | Kill/restart own collector; require denial persists | Passed in VM |
| Driver unload/recovery | Explicit unload/read/reload/read; targeted standard Verifier | Passed in VM |
| Browser update / replacement | Wrong pin rejection automated; loaded-image race unresolved | Wrong-pin rejection passed; mapped-image race deferred |
| Real Chrome/Edge/Firefox own-profile access | Per-browser image-bound trust + owner/profile policy | Deferred to Phase 3 |
| Cross-browser denial / scoped backup exceptions | Multi-browser policy grants | Deferred to Phase 3 |
| Name query failure / message fuzz / pool failures | Debugger fault injection and privileged fuzzing | Procedure provided; unrun |

## Assumptions, bypasses and next implementation steps

The PoC assumes stable local NTFS fixture paths and a trusted privileged service,
configuration and image artifacts. Normalized paths are not file identities.
Outside hard links, namespace races, pre-existing/duplicated handles and mappings
remain gaps. Disk verification of an already running image does not prove its
mapped bytes. Kernel attackers, privileged tampering and browser injection are
excluded. No complete browser-session-theft protection is claimed.

1. Review callback lifetime/IRQL behavior and extend analysis beyond the minimum
   driver ruleset where useful. Compile/analysis/lint checks have passed, but are
   not a substitute for runtime review and fault injection.
2. Extend the completed signed-VM/Verifier checks with long-running stress,
   comprehensive aliases, fault injection, message fuzzing and leak analysis.
3. Resolve object/namespace and process-creation image binding before expanding
   the claimed security boundary. Measure performance and availability effects.
4. Extend the notifier's read-only per-user discovery into validated atomic
   browser/category policy snapshots; validate genuine SQLite/LevelDB and browser subprocess flows.
5. Add owner-scoped browser grants and expiring backup exceptions; exercise real
   browser updates, replacement races, cross-browser denial and service recovery.
6. Obtain an allocated altitude, choose an open-source license and establish
   release signing/review before distributing a driver.

## Tray and credential discovery, 2026-11-05

The .NET 9 tray notifier builds with zero warnings/errors. Its 49 self-checks
cover malformed/partial UTF-8 telemetry, oversized records, log truncation and
rotation, heartbeat age/PID reuse, name-query failure alerts, multi-profile
location discovery, embedded partitions, secret files held with FileShare.None,
manual candidates and path exclusions. The existing C++ suites (92 assertions)
still pass after adding the collector heartbeat.

A command-only smoke test runs the resident WinForms event loop with the
dashboard hidden and popups disabled, processes one injected telemetry fixture,
and requires clean timed shutdown. This does not test a kernel denial or visual
layout. Subsequent user-authorized interactive GUI checks confirmed the target
list, unprotected/offline status, explicitly labelled display-test alert,
history row and diagnostics view. Closing the dashboard left the resident
event loop running with popups enabled. Actual host metadata discovery found Chrome/Edge/Firefox and a packaged
Codex embedded-browser layout. All real target candidates remain unprotected;
the host driver remains unloaded. See [scope and commands](NOTIFIER.md).
