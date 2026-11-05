# Disposable VM test report — 2026-11-05

## Environment and scope

Hyper-V generation 2 VM `BDG-Lab-Win11`, 2 virtual CPUs, 4 GiB RAM, a dynamic
64 GiB OS disk and a separate 8 GiB NTFS test disk (`X:`). No virtual switch is
connected; management uses PowerShell Direct. The guest is Microsoft's Japanese
Windows 11 Enterprise LTSC 2024 evaluation image. ISO SHA-256:
`B15AD6F38D6EA6D04A516A986B0032CBBD8E3BA22B8B648746ED5FF3A6992066`.
The downloaded setup.exe signature was verified as Microsoft Corporation.

Release binaries were used. A short-lived code-signing certificate was created
and trusted **inside the guest only**. The signed SYS, generated CAT and signed
CAT were verified in the guest. Lab altitude `89999.9001` was checked for conflicts;
it is not a Microsoft allocation. A baseline checkpoint was taken before driver
installation. No real browser profiles were discovered or accessed.

## Results

| Check | Result |
| --- | --- |
| Initial suite | 37/37 recorded checks passed |
| Extended suite under Driver Verifier | 40/40 recorded checks passed |
| New unauthorized read, copy, mapping, write, truncate, delete and rename-open | Denied |
| Metadata-only open and unrelated sibling | Allowed |
| Designated process object | Allowed; a different process using the same EXE was denied |
| Synthetic multiple profiles, SQLite companions, Local Storage | Denied to unregistered processes |
| Concurrent reads | Denied |
| Collector crash and restart | Denial continued |
| Wrong executable hash | Registration rejected; subsequent access denied |
| Audit overload with no collector | All 96 reads denied; loss counter rose from 0 to 33 |
| Audit loss notification | Delivered to the restarted collector |
| Unload / read / reload / read | Read succeeded while unloaded, then denied after reload |
| Existing handle and mapping across load | Remained readable: **known gaps confirmed** |
| Existing hard link outside root | Read succeeded: **known gap confirmed** |
| Repeated configuration | Preserved minifilter instance registration |

Recorded checks include an explicitly labelled known-gap observation; the totals
must not be interpreted as 40 protected scenarios or as complete theft prevention.
Driver Verifier targeted only `BdgDriver.sys`; recorded standard flags were
`0x001209bb`. The kernel remained responsive through the exercised checks and
unload/reload. This is a finite synthetic run, not exhaustive stability proof.

## Defects found and corrected

* `Configure-LabVm.ps1` used Registry `New-Item -Force`, which replaced Parameters
  and removed the INF-installed Instances subtree. It now creates the key only
  when absent. The VM runner checks preservation before and after two repeated
  configuration calls. The original failure was preserved before restoring the
  baseline checkpoint and rerunning.
* A zero-rights Win32 truncate is rejected with error 87 before filter enforcement.
  The runtime suite now uses a valid write-capable truncate request; the invalid
  API case remains a separate native-probe test.
* Queue lock wrappers now declare SAL acquire/release contracts, enabling clean
  recommended-rule analysis.
* The recovery harness retains child process handles and captures real exit codes.
  Verifier's GUI-subsystem executable is explicitly waited on. A reset return of
  2 is accepted only when both registry flags and selected drivers are cleared.

Removal validation found a disabled, stopped residual BDG service after the package
API returned success. A guest reboot completed the pending removal. Final evidence
confirms `packageRemoved=true`, `serviceAbsent=true`, and `rebootRequired=false`.
Verifier's selected drivers and flags are clear, and the VM was shut down normally
(`Off`). The final pass did not need the guarded residual-service SCM fallback.
Evidence is in `results/cleanup/diagnostics/uninstall.json` and the adjacent Verifier
state record. The guest's registry reports build 26100.1742 / 24H2.

## Evidence and remaining work

Generated evidence is under `out/vm/BDG-Lab-Win11/results/`: `baseline`,
`verifier-resumed`, `cleanup`, and diagnostic runs. Each successful access run has
`vm-results.json`, JSONL access/loss events, instance/status records, and recovery
evidence. The VM manifest and checkpoint are under the same VM directory. Generated
files, media, test certificates and private guest credentials are ignored by Git.

Unvalidated: real browsers and real SQLite/LevelDB recovery, kernel message fuzzing,
fault injection, long-running stress, forced PID reuse, process-image replacement
races, and comprehensive namespace manipulation. Browser discovery and browser
policy activation are still future work. No host boot policy or certificate trust
was changed and no BDG driver was installed or loaded on the host.
