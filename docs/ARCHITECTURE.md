# Architecture and feasibility

Phase 1 design, written before kernel implementation. The initial deliverable is a
**synthetic-directory, x64 Windows 11 PoC**, not a browser protection product.

## Components and data flow

* `driver/`: WDK C minifilter. Immutable protected root loaded from an
  administrator-owned registry value at DriverEntry; one referenced trusted
  process object; local pre-create decisions; bounded audit ring.
* `service/`: C++20 console/SCM service. Connects through Filter Manager, verifies
  an explicitly configured process, distributes its identity, polls events, and
  writes JSON Lines. It never receives a synchronous access-decision request.
* `notifier/`: interactive .NET tray dashboard/alerts and read-only per-user
  browser/credential discovery, separate from session 0; optional console viewer.
* `shared/`: versioned, fixed-width x64 wire interface and shared policy helpers.
* `tests/`: executable policy tests and native Windows access probes; VM procedure.

The driver attaches only to the local NTFS volume containing the configured root.
It starts with **no trusted process**. Protection of that root does not depend on
the service being connected. A disconnect revokes the trusted identity, retaining
the root. A malformed command cannot clear the root. Changing roots requires an
explicit unload/reconfigure/reload maintenance window, during which protection
is absent. Configuration does not persist across a driver unload by magic.

## Phase 2 enforcement contract

The root must be a canonical NT device path ending in `\BDG-Lab\Protected`.
This restriction makes accidental live-profile activation harder; it is not a
security mechanism against administrators. The VM setup creates only fixtures.

`IRP_MJ_CREATE` is inspected **before the filesystem grants an open**. Normalized
names are matched case-insensitively with a component boundary, including the
root itself and alternate streams (`:`). Unauthorized content/execute opens,
write/delete/security-changing access, MAXIMUM_ALLOWED, mutating dispositions,
and delete-on-close are completed with `STATUS_ACCESS_DENIED`, zero information.
Metadata-only `FILE_OPEN` requests pass. Directory listing uses the same access
bit as file reading and is therefore denied within the root. The trusted process
is allowed normal opens; ordinary filesystem ACL checks still apply.

Name-query failure on the selected volume denies a sensitive create even outside
the root, with a distinct reason in audit. This deliberately favors confidentiality
over availability. A trusted process is also subject to this error rule. There is
no blanket SYSTEM, kernel-mode, process-name, parent, or service-process exemption.
Other volumes are not attached. The broad failure rule needs stress testing before
any production use. Cleanup/close and paging IO are never failed by this PoC.

No callbacks are registered for read, write, set-information, or section
synchronization. New denied handles cannot be used for CopyFile or mappings, but
**already granted handles and namespace aliases remain gaps**. A post-create
cancel would be too late to undo a destructive create and is not used as the
primary decision point. Name tunneling means normalized pre-create names are
not a permanent file identity. See SECURITY_BOUNDARIES.md.

## Process trust

The privileged service opens and retains a process handle. It checks the process
token user against an explicit SID, the full image path against an explicit
expected path, and an administrator-provided SHA-256 pin. It opens the image
without write/delete sharing, hashes that handle, and evaluates Authenticode on
that handle. Signature failure rejects trust unless `--allow-unsigned-lab` was
explicitly requested. The unsigned mode is for the synthetic helper only. A
valid signature alone never grants trust; publisher identity by itself is not
an authorization rule. Hash mismatch always fails, including in unsigned mode.

The service submits its **open process handle**, not a PID, on its own connection.
`ObReferenceObjectByHandle(UserMode, *PsProcessType)` validates rights/type in the
calling process. The driver holds the resulting opaque `PEPROCESS` reference and
compares it to `FltGetRequestorProcess`. Pinning the object prevents PID recycling
from inheriting an exception. No EPROCESS fields or undocumented APIs are used.
The port DACL allows only SYSTEM and elevated administrators, one connection.
These principals are part of the trusted computing base.

An open image path and a verified disk file do **not** prove that an already
running process mapped those exact bytes. Replacement before verification,
ancestor-directory races, existing writable mappings, injection, and mutable
install locations are unresolved. This is why arbitrary browser trust and
production discovery are deferred. Browser integration requires process-creation
tracking and binding the creation image file object/identity to the verified
artifact, immutable install ACLs, owner SID, browser identity, and profile scope.

## Audit and failure handling

Pre-create only appends to a fixed 64-record ring, with no user-mode wait or disk
IO. Short push-lock critical sections keep IRQL at or below APC_LEVEL when copying
pageable name information and replies; no user buffer is accessed under a lock.
Events retain a bounded process reference so passive-level drain can obtain
its image via `SeLocateProcessImageName` without PID-reuse misattribution. Queue
overflow drops telemetry, never changes denial; a cumulative loss counter is
returned with every reply. Paths are bounded and truncation is flagged. No file
contents or cookie values are logged. Service log IO failure exits nonzero and
closes the port, revoking trust. Ring events are not durable during driver unload.
Attachment health is an approved-instance count, cleared at teardown start, and
must also be checked with `fltmc instances` during activation. The collector exits
on a subsequent unarmed reply rather than reporting a detached volume as healthy.

The viewer reads JSONL and displays time, image/name, browser (`Synthetic`),
category (`TestData`), decision, and target. It cannot alter policy. Production
notification IPC should use a read-only per-user channel with owner filtering.
The collector now emits synthetic-mode heartbeat records every two seconds;
the tray validates freshness and process creation time. It always reports
real-browser/credential candidates as unprotected. See [notifier details](NOTIFIER.md).

## Browser integration design (Phase 3, not activated here)

Discovery runs in the target user's context, not under SYSTEM's AppData. Enumerate
Chrome and Edge user-data roots, `Local State` profile entries and actual profile
directories; support per-user/system installs and explicitly configured custom
`--user-data-dir` roots. Discover Firefox using `profiles.ini`, `installs.ini`,
relative and absolute profile paths, plus directory validation. Never assume
`Default` or a single Firefox profile. Reconcile changes with directory watches
and periodic full scans; close activation gaps before advertising protection.

Generate exact-file rules for Chromium `Network/Cookies`, legacy profile-level
`Cookies`, and each `-wal`, `-shm`, `-journal` companion, plus user-data `Local State`.
Generate subtree rules for `Local Storage/leveldb`. Firefox rules cover
`cookies.sqlite` and companions, legacy `webappsstore.sqlite` and companions,
`storage/default` local storage (version-aware `ls`/`data.sqlite` layouts) and
relevant profile storage metadata. `storage/default` can include unrelated
origin data; minimize scope only after version-specific validation. Do not
protect all cache directories. Discovery reports unknown layouts as degraded,
never as successfully protected.

Future immutable policy snapshots need a generation, owner SID, browser identity,
volume/file IDs, exact/subtree category, process identity grants, and expiry-bound
backup/migration exceptions. Browser A must not receive browser B's grant.
Validate snapshots completely before atomic publication; retain old policy on
failure. Automatic browser update trust is a new verification, not a name match.
Read-only location discovery is now implemented in the notifier. It uses profile
directory evidence rather than reading Chromium Local State, reads only bounded
Firefox location INI manifests, and skips reparse paths. It does not read browser
databases, auth files or key contents and does not apply policy. Credential and
embedded-browser candidates and limitations are detailed in [NOTIFIER.md](NOTIFIER.md).

## Required tooling and documented interfaces

VS 2022 C++ desktop tools, matching Windows 11 SDK/WDK and VS WDK integration;
`WindowsKernelModeDriver10.0`, `fltKernel.h`, `FltMgr.lib`, InfVerif, Inf2Cat,
SignTool, MSBuild; WinDbg and Driver Verifier in a disposable VM. User mode uses
v143, C++20, FltLib, BCrypt, WinTrust, Advapi32 and Shell32.

Primary references:

* [Minifilter IO rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/filtering-i-o-operations-in-a-minifilter-driver)
* [Name tunneling](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltgettunneledname)
* [Section synchronization constraints](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization)
* [Filter Manager communication](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/communication-between-user-mode-and-kernel-mode)
* [Message buffer validation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nc-fltkernel-pflt_message_notify)
* [Default port DACL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltbuilddefaultsecuritydescriptor)
* [INF and 24H2 registry layout](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver)
* [Altitude allocation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)
* [WinVerifyTrust file handles](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_file_info)
