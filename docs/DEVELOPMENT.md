# Development and disposable-VM procedure

## Development environment

Run `scripts/Get-Environment.ps1` for a read-only inventory. As of 2026-11-05,
the development host reports Windows 10.0.26300.0, VS 2022 Community 17.14,
MSBuild 17.14, MSVC 19.44, SDKs 10.0.22621/10.0.26100 and CMake 4.4.4. SDK headers
and x64 user libraries exist. WDK 26100.6584 was installed from Microsoft's signed
installer, along with the VS 2022 Windows Driver Kit component and latest v143
x64/x86 Spectre libraries. Both installers returned success without a reboot.
Kernel headers (`km/fltKernel.h`), x64 FltMgr.lib and WDK MSBuild integration now
exist. Python is not required by this project.

For a new VS 2022 machine, select WDK 26100.6584 from Microsoft's
[supported WDK table](https://learn.microsoft.com/en-us/windows-hardware/drivers/other-wdk-downloads).
The default latest WDK currently targets VS 2026, so do not choose it blindly for
VS 2022. Add `Component.Microsoft.Windows.DriverKit` and
`Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre` using VS Installer,
then install the matching WDK. Build-number matching is required; QFE revisions
may differ. Save work and close active build processes before modifying VS.

## User-mode build

```powershell
.\scripts\Build.ps1 -Configuration Debug
# Equivalent commands:
cmake -S . -B out/user -G "Visual Studio 17 2022" -A x64
cmake --build out/user --config Debug --parallel
ctest --test-dir out/user -C Debug --output-on-failure
```

Executables are under `out/user/Debug`. The CMake-generated solution is suitable
for VS/MSBuild. MSVC `/W4 /WX` is enabled. Local tests touch only their own test
image and process identity; they do not connect to a driver or inspect profiles.
The independent pin calculation uses PowerShell Get-FileHash.

## Kernel build and package (build machine, no loading)

Install a matching Windows 11 SDK, WDK, and VS 2022 WDK extension through their
official installers. Open `driver/BdgDriver.vcxproj` in Visual Studio or run:

```powershell
.\scripts\Build.ps1 -Configuration Debug -Driver
```

The driver project emits `out/driver/Debug/BdgDriver.sys` and deliberately disables
automatic signing/deployment. Run current WDK static analysis and InfVerif as well
as compilation. The x64 Debug build now passes with `/W4 /WX`. Minimum-rule driver
static analysis was also run successfully with the following additional MSBuild
arguments: `/t:Rebuild /p:RunCodeAnalysis=true`. Compiler logs confirm `/analyze`,
`DriverMinimumRules.ruleset`, WindowsPrefast and driver analysis plugins were used.
This is not a Driver Verifier or VM runtime result.

The build script selects the newest installed matching SDK/WDK pair with actual
kernel headers and x64 FltMgr.lib, and disables MSBuild node reuse so idle build
workers do not block subsequent tool maintenance.

InfVerif 10.0.26100.6584 accepted a generated copy of the INF template with a
lint-only numeric altitude substitution. That copy lives in `out/validation-inf`,
is explicitly labelled **do not install/distribute**, and assigns no altitude to
BDG. The real package still needs the lab/release altitude selection below.

There is no fabricated Microsoft altitude in the repository. Obtain a unique
allocated altitude before any distribution. For an isolated test VM, explicitly
select an unused **lab-only** value in the Security Enhancer range (80000–89999),
check the VM's `fltmc filters` for conflicts, then render the template:

```powershell
$labAltitude = '<your-isolated-test-value>'
.\scripts\Stage-DriverPackage.ps1 -DriverBinary .\out\driver\Debug\BdgDriver.sys -TestAltitude $labAltitude -LabOnly
```

This writes an unsigned package to `out/package`. A test altitude is not a
Microsoft allocation. The INF uses demand-start, DIRID 13, the SecurityEnhancer
class, FltMgr dependency and OS-decorated instance settings: `Instances` before
24H2 and `Parameters\Instances` on 24H2+. No broad protected path is installed.

Use SignTool to embed-sign the SYS with a lab code-signing certificate, run
Inf2Cat for the target OS and sign the resulting CAT. Use the OS identifier
reported by your WDK's `Inf2Cat /?` for the VM build. For example, from a WDK
developer prompt, with your lab certificate thumbprint and package path:

```powershell
signtool sign /v /fd SHA256 /s My /sha1 $labCertificateThumbprint .\out\package\BdgDriver.sys
# Replace $targetOs with the identifier supported by the installed WDK.
Inf2Cat /driver:.\out\package /os:$targetOs
signtool sign /v /fd SHA256 /s My /sha1 $labCertificateThumbprint .\out\package\BdgDriver.cat
signtool verify /v /pa .\out\package\BdgDriver.sys
```

Follow Microsoft's [test-signing instructions](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/test-signing)
for certificate creation and VM trust. Do not put private keys into the repository.
Unsigned, unvalidated artifacts must not be presented as installable releases.

## Disposable Windows 11 VM preparation

Use a snapshot, debugger connection, a local fixed NTFS test volume (prefer a
dedicated virtual disk such as `X:`), and no real browser data. The broad name-error
failure policy makes testing on the OS volume less desirable. Have console access
and a snapshot restore route. Use only the VM for certificate trust changes and
test-signing mode; Secure Boot policies may restrict these changes. Do not weaken
the development host's boot policy. Enable Driver Verifier only for BdgDriver.sys,
not all installed drivers; collect crash dumps before iterating.

Copy the binaries, signed package and repository procedures into the VM.
Run the following **inside the VM** in an elevated PowerShell window:

1. Create fixtures before filter activation:

   ```powershell
   .\scripts\Initialize-Lab.ps1 -VolumeRoot X:\
   ```

   The script refuses to overwrite an existing lab. It creates browser-shaped text
   fixtures and one deliberate outside hard link. It never discovers profiles.

2. Install the signed primitive-driver package by right-clicking its generated
   `BdgDriver.inf` and selecting **Install**. Verify installation succeeded and
   `sc.exe qc BdgDriver` points to the expected package. Package staging alone is
   not evidence of service installation. Production installers should use the
   documented `DiInstallDriver` / `DiUninstallDriver` primitive-driver lifecycle.

3. Configure the fixed root. This writes only the driver's VM registry values and
   does **not** load it:

   ```powershell
   .\scripts\Configure-LabVm.ps1 -ServiceExe .\out\user\Debug\bdg-service.exe -LabBase X:\BDG-Lab -DisposableVm
   ```

4. Explicitly load and verify attachment, with no browser processes involved:

   ```powershell
   fltmc load BdgDriver
   fltmc instances -f BdgDriver
   .\out\user\Debug\bdg-service.exe --status
   ```

   Expect exactly the selected NTFS volume and `armed=1`, `trusted=0`. Any error,
   wrong volume or absent instance is a failed activation. Missing/invalid root
   configuration must fail DriverEntry. No automatic allow-all fallback exists.

## Automated synthetic VM tests

Keep the standalone service stopped before testing (one privileged port client).
Use elevated PowerShell 7 in the VM:

```powershell
.\tests\Invoke-VmTests.ps1 -Binaries .\out\user\Debug -LabBase X:\BDG-Lab -DisposableVm
```

It checks unauthorized reads/copies/new mappings, write/delete/rename-open denial,
metadata access, sibling boundary, synthetic multiple profiles and WAL companions,
concurrency, exact process-object grants, audits, service crash/restart and stale
hash rejection. The outside hard-link success is labelled **KNOWN GAP**. The script
does not install/load/unload a driver. It starts and stops only its own user-mode
children, leaves fixtures intact and records `X:\BDG-Lab\vm-results.json` plus JSONL
logs. A failure stops the suite and preserves partial results. This suite is not
registered with host CTest. It has now passed in the dedicated evaluation VM;
see [the VM report](VM_TEST_REPORT.md) for evidence and scope.

## Automated Hyper-V lab workflow

The repository now includes `New-LabVm.ps1`, `Initialize-LabGuest.ps1`,
`Test-LabGuest.ps1` and `Invoke-LabVm.ps1`. They create and manage only a new,
marked BDG VM below `out/vm`; they reject unrelated VM identities and disk paths.
Use an elevated Windows PowerShell window for Hyper-V management and PowerShell
7 for local/guest test suites. Release binaries, WDK 26100 tools and the standard
PowerShell 7/VS redist paths used by the provisioning script must be available.

```powershell
.\scripts\Build.ps1 -Configuration Release
.\scripts\Build.ps1 -Driver -Configuration Release
.\scripts\New-LabVm.ps1 -IsoPath '<official evaluation ISO path>' -DisposableVm -Start
$manifest = '.\out\vm\BDG-Lab-Win11\manifest.json'
.\scripts\Invoke-LabVm.ps1 -ManifestPath $manifest -Action Initialize
.\scripts\Invoke-LabVm.ps1 -ManifestPath $manifest -Action Package
.\scripts\Invoke-LabVm.ps1 -ManifestPath $manifest -Action Checkpoint
.\scripts\Invoke-LabVm.ps1 -ManifestPath $manifest -Action Run
.\scripts\Invoke-LabVm.ps1 -ManifestPath $manifest -Action Recover
.\scripts\Invoke-LabVm.ps1 -ManifestPath $manifest -Action Collect -Label baseline
```

Only the new, path-verified VHDX is initialized/formatted. BCDBoot uses an explicit
guest EFI target, and BCDEdit uses an explicit offline guest store. Certificate
trust and test signing apply to the guest. Credentials are generated locally and
stored as host-user DPAPI-protected CLIXML in a restricted directory; do not publish
that directory. No virtual switch is connected. `Start` resumes a stopped VM;
`RestoreBaseline` restores only this VM's `BDG-before-driver` checkpoint.

For Verifier, use `EnableVerifier`, `Restart`, `Run`, `Recover`, and `Collect` with a
fresh evidence label. Finish with `DisableVerifier`, `Uninstall`, `Collect` and
`Stop`. An uninstall may require a VM reboot to complete. No script should treat
a disabled residual service as proof of complete removal. Configuration must
preserve the INF-created Instances keys; Registry `New-Item -Force` is deliberately
not used for an existing Parameters key.

View notifications in an interactive session that has permission to read the log:

```powershell
.\notifier\Watch-Bdg.ps1 -LogPath X:\BDG-Lab\events-<run-id>.jsonl
```

The service appends UTF-8 JSONL with no file contents. A BDG `allow` event means
the filter permitted the request; filesystem ACLs can still deny it. Empty image
or truncation flags indicate incomplete telemetry. Audit-loss records must be
visible, never interpreted as an absence of attacks.

## Console service and SCM mode

For a collector with no trusted process:

```powershell
.\out\user\Debug\bdg-service.exe --console --log X:\BDG-Lab\events.jsonl
```

To designate a synthetic helper, supply `--trust-pid`, `--image` (absolute path),
`--sha256`, and `--owner-sid`. Authenticode is required by default, with cached
revocation checking; offline cache failures reject trust. The VM test suite
explicitly uses `--allow-unsigned-lab` for the unsigned, hash-pinned helper.
There are no automatic process-name or parent-process exceptions.

For SCM mode, place the EXE/configuration in an administrator-owned directory
and give LocalSystem a writable log destination outside Protected. Example
manual VM registration of a deny-all collector:

```powershell
sc.exe create BdgService binPath= '"C:\BDG\bdg-service.exe" --service --log "X:\BDG-Lab\service.jsonl"' start= demand depend= BdgDriver
sc.exe start BdgService
sc.exe query BdgService
sc.exe stop BdgService
sc.exe delete BdgService
```

This does not authorize any browser. SID/profile ownership for real browser
users and long-lived process discovery are not implemented. Service startup
failure is reported as stopped with an error; console mode prints the cause.
Install paths, service ImagePath, hash pins and log directory ACLs are part of
the trusted configuration. Avoid exposing logs containing user paths to others.

## Existing handles, mappings and lifecycle procedure

Perform these additional tests against fixtures in the VM, from a clean snapshot.
Use native probe `hold-read` and `hold-map`, whose gate wait occurs after acquiring
the handle/view. The gate/ready events must be created in the same user session.

```powershell
$gate = [Threading.EventWaitHandle]::new($false, 'ManualReset', 'Local\BdgHeldGate')
$ready = [Threading.EventWaitHandle]::new($false, 'ManualReset', 'Local\BdgHeldReady')
# With the filter UNLOADED, start either hold-read or hold-map:
$held = Start-Process .\out\user\Debug\bdg-probe.exe -ArgumentList '--gate Local\BdgHeldGate --ready Local\BdgHeldReady hold-map X:\BDG-Lab\Protected\Chrome\Default\Network\Cookies' -PassThru -WindowStyle Hidden
if (!$ready.WaitOne(10000)) { throw 'Probe was not ready' }
fltmc load BdgDriver
fltmc instances -f BdgDriver
$gate.Set()
$held.WaitForExit()
$held.ExitCode # Expected 0: an explicitly documented protection gap.
$gate.Dispose(); $ready.Dispose()
```

Repeat with `hold-read`, then with a handle inherited/duplicated from a trusted
process to a new untrusted process. Those reads are also gaps. No handle or
mapping revocation claim is permitted. New untrusted opens must still fail.

Try hard-link creation and rename using handles opened before activation, rename
the protected ancestor while holding DELETE, create outside junctions to the root,
inside junctions to outside data, case/8.3 aliases and OpenFileById. Record whether
each is denied or bypasses, together with volume/file IDs. A denied ordinary
rename test does not establish rename safety for earlier handles. Restore the
snapshot between namespace tests so results do not depend on a previous mutation.

Test audit overload by issuing more than 64 denied creates with the collector
stopped; after starting it, require a nonzero cumulative loss count while all
denials remained effective. In a debugger, inject pool/name-query failures and
malformed/truncated/unaligned message buffers; require rejection, no policy
relaxation and no leak. Fuzzing these privileged interfaces is still necessary.

## Unload, removal and recovery (VM only)

Stop the collector or SCM service, close fixture handles, then explicitly run:

```powershell
fltmc unload BdgDriver
fltmc filters
.\out\user\Debug\bdg-probe.exe read X:\BDG-Lab\Protected\Chrome\Default\Network\Cookies
# Expected success now: unloading intentionally ends protection.
fltmc load BdgDriver
.\out\user\Debug\bdg-probe.exe read X:\BDG-Lab\Protected\Chrome\Default\Network\Cookies
# Expected denial again, with no trusted process.
```

Repeat during concurrent access and under targeted Driver Verifier. Require a
clean unload with no outstanding pool/process references or bugchecks. Manual
detach is refused by the PoC; unload is its explicit maintenance operation.

Unload before uninstalling. Identify the package's published `oemNN.inf` using
`pnputil /enum-drivers` and verify provider/original INF. Remove that exact package
with `pnputil /delete-driver oemNN.inf /uninstall`; honor any reboot requirement.
For production lifecycle code use `DiUninstallDriver`; never delete Driver Store
files manually. Confirm service/package removal, remove only BDG's VM test
certificate trust entries and restore the snapshot/test boot settings. No removal
script guesses package names or deletes arbitrary paths.

If the VM becomes unstable, restore its snapshot. Demand-start prevents automatic
reloading on the next boot unless an operator configured other startup behavior.
Reboot after serious filesystem errors and collect dumps; do not repeatedly load
an unreviewed failing kernel binary. No kernel validation success is implied by
these instructions.
