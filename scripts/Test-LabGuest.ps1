#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$VmId,
    [Parameter(Mandatory)][ValidateSet('SignCatalog','Run','Recover','Uninstall','EnableVerifier','DisableVerifier')][string]$Action
)
$ErrorActionPreference = 'Stop'
$guest = 'C:\BDG'
if ($env:COMPUTERNAME -ne 'BDG-LAB' -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or
    (Get-Content -LiteralPath "$guest\.bdg-disposable-vm" -Raw).Trim() -ne $VmId.ToString()) {
    throw 'This script can run only inside the marked BDG disposable VM.'
}
$manifest = Get-Content -LiteralPath "$guest\guest-manifest.json" -Raw | ConvertFrom-Json
if ($manifest.vmId -ne $VmId.ToString()) { throw 'Guest manifest identity mismatch.' }
$package = "$guest\package"
$diagnostics = "$guest\diagnostics"
New-Item -ItemType Directory -Path $diagnostics -Force | Out-Null
function Run-Probe([string]$Label,[int]$Expected,[string[]]$Arguments) {
    $safeLabel = $Label.Replace(' ','-')
    $stdout = Join-Path $diagnostics "$safeLabel.stdout.txt"
    $stderr = Join-Path $diagnostics "$safeLabel.stderr.txt"
    $quoted = @($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $probe = Start-Process -FilePath "$guest\bin\bdg-probe.exe" -ArgumentList $quoted -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -Wait
    if ($probe.ExitCode -ne $Expected) { throw "$Label failed: exit=$($probe.ExitCode), expected=$Expected" }
    Write-Output "$Label passed (exit=$Expected)."
}
function Run-Verifier([string]$Label,[string]$Arguments) {
    $stdout = Join-Path $diagnostics "$Label.txt"
    $stderr = Join-Path $diagnostics "$Label.stderr.txt"
    $process = Start-Process -FilePath "$env:windir\System32\verifier.exe" -ArgumentList $Arguments -WindowStyle Hidden `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -Wait
    return [int]$process.ExitCode
}
if ($Action -eq 'SignCatalog') {
    & "$guest\signtool.exe" sign /v /sm /s My /sha1 $manifest.certificateThumbprint /fd SHA256 "$package\BdgDriver.cat"
    if ($LASTEXITCODE -ne 0) { throw 'Guest CAT signing failed.' }
    foreach ($file in @('BdgDriver.sys','BdgDriver.cat')) {
        & "$guest\signtool.exe" verify /v /pa (Join-Path $package $file)
        if ($LASTEXITCODE -ne 0) { throw "Guest signature verification failed: $file" }
    }
    $manifest.stage = 'catalog-signed'
    $manifest | ConvertTo-Json | Set-Content -LiteralPath "$guest\guest-manifest.json" -Encoding utf8
    return
}
if ($Action -eq 'EnableVerifier' -or $Action -eq 'DisableVerifier') {
    $arguments = if ($Action -eq 'EnableVerifier') { '/standard /driver BdgDriver.sys' } else { '/reset' }
    $verifierCode = Run-Verifier "$Action-configure" $arguments
    Run-Verifier $Action '/querysettings' | Out-Null
    $settings = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $driversCleared = [string]::IsNullOrWhiteSpace((@($settings.VerifyDrivers) -join ' ')) -and !$settings.VerifyDriverLevel
    # /reset can report 2 when no drivers remain selected. Accept it only after
    # independently checking both the driver list and verifier flags are clear.
    if ($verifierCode -ne 0 -and !($Action -eq 'DisableVerifier' -and $verifierCode -eq 2 -and $driversCleared)) {
        throw "Verifier configuration failed: exit=$verifierCode; $((Get-Content -LiteralPath (Join-Path $diagnostics "$Action-configure.txt")) -join ' ')"
    }
    [ordered]@{ verifiedDrivers=$settings.VerifyDrivers; verifyDriverLevel=$settings.VerifyDriverLevel } | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $diagnostics "$Action-registry.json") -Encoding utf8
    if ($Action -eq 'EnableVerifier' -and ($settings.VerifyDrivers -notmatch 'BdgDriver\.sys' -or !$settings.VerifyDriverLevel)) {
        throw 'Verifier registry settings do not target BdgDriver.sys.'
    }
    if ($Action -eq 'DisableVerifier' -and !$driversCleared) { throw 'Verifier settings remain enabled after reset.' }
    Write-Output "$Action complete; restart only this VM to apply it."
    return
}
if ($Action -eq 'Uninstall') {
    if ((& fltmc.exe filters) | Where-Object { $_ -match '^BdgDriver\s' }) { throw 'Unload the lab driver before uninstalling it.' }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BdgLabDriverUninstaller {
  [DllImport("newdev.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool DiUninstallDriverW(IntPtr window, string infPath, uint flags,
    [MarshalAs(UnmanagedType.Bool)] out bool rebootRequired);
  [StructLayout(LayoutKind.Sequential)]
  struct ServiceStatus { public uint type, state, controls, win32Exit, serviceExit, checkpoint, waitHint; }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  static extern IntPtr OpenServiceW(IntPtr manager, string name, uint access);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus status);
  [DllImport("advapi32.dll", SetLastError=true)]
  static extern bool DeleteService(IntPtr service);
  [DllImport("advapi32.dll")]
  static extern bool CloseServiceHandle(IntPtr service);
  public static int DeleteStoppedBdgService() {
    IntPtr manager=OpenSCManagerW(null,null,1);
    if(manager==IntPtr.Zero) return Marshal.GetLastWin32Error();
    IntPtr service=IntPtr.Zero;
    try {
      service=OpenServiceW(manager,"BdgDriver",0x10004);
      if(service==IntPtr.Zero) return Marshal.GetLastWin32Error();
      ServiceStatus status;
      if(!QueryServiceStatus(service,out status)) return Marshal.GetLastWin32Error();
      if(status.type!=2 || status.state!=1) return 1061;
      return DeleteService(service) ? 0 : Marshal.GetLastWin32Error();
    } finally { if(service!=IntPtr.Zero) CloseServiceHandle(service); CloseServiceHandle(manager); }
  }
}
'@
    $rebootRequired = $false
    $installedPackages = @(Get-WindowsDriver -Online -All | Where-Object {
        [IO.Path]::GetFileName($_.OriginalFileName) -ieq 'BdgDriver.inf' -and $_.ProviderName -eq 'Browser Data Guard contributors'
    })
    if ($installedPackages.Count -gt 1) { throw 'More than one BDG package is installed; refusing ambiguous removal.' }
    $removed = $installedPackages.Count -eq 0
    if (!$removed) {
        $removed = [BdgLabDriverUninstaller]::DiUninstallDriverW([IntPtr]::Zero,$installedPackages[0].OriginalFileName,0,[ref]$rebootRequired)
        if (!$removed) { throw "DiUninstallDriver failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    }
    $serviceCleanupRequired = Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\BdgDriver'
    if ($serviceCleanupRequired) {
        $registration = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\BdgDriver'
        if ($registration.Type -ne 2 -or $registration.Start -ne 4 -or
            $registration.ImagePath -notmatch '\\FileRepository\\bdgdriver\.inf_amd64_[^\\]+\\BdgDriver\.sys$') {
            throw 'Residual service is not the disabled, stopped BDG lab driver; refusing service deletion.'
        }
        $deleteCode = [BdgLabDriverUninstaller]::DeleteStoppedBdgService()
        "SCM DeleteStoppedBdgService result: $deleteCode" | Set-Content -LiteralPath (Join-Path $diagnostics 'service-delete.txt')
        if ($deleteCode -notin @(0,1060,1072)) { throw "Residual BDG service deletion failed: $deleteCode" }
        if ($deleteCode -eq 1072) { $rebootRequired = $true }
    }
    $serviceAbsent = !(Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\BdgDriver')
    if (!$serviceAbsent -and !$rebootRequired) { throw 'BDG service registration remains after uninstall.' }
    [ordered]@{ vmId=$VmId.ToString(); packageRemoved=$removed; serviceAbsent=$serviceAbsent; rebootRequired=$rebootRequired; residualServiceCleanup=$serviceCleanupRequired } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $diagnostics 'uninstall.json') -Encoding utf8
    Write-Output "Driver package removed; serviceAbsent=$serviceAbsent rebootRequired=$rebootRequired."
    return
}
$cookie = 'X:\BDG-Lab\Protected\Chrome\Default\Network\Cookies'
if ($Action -eq 'Recover') {
    & fltmc.exe unload BdgDriver
    if ($LASTEXITCODE -ne 0) { throw 'Clean driver unload failed.' }
    Run-Probe 'read after unload' 0 @('read',$cookie)
    $held = @()
    try {
        foreach ($operation in @('hold-read','hold-map')) {
            $tag = [guid]::NewGuid().ToString('N')
            $gateName = "Local\BdgRecoveryGate-$tag"; $readyName = "Local\BdgRecoveryReady-$tag"
            $gate = [Threading.EventWaitHandle]::new($false,'ManualReset',$gateName)
            $ready = [Threading.EventWaitHandle]::new($false,'ManualReset',$readyName)
            $args = "--gate $gateName --ready $readyName $operation $cookie"
            $start = [Diagnostics.ProcessStartInfo]::new("$guest\bin\bdg-probe.exe")
            $start.Arguments = $args
            $start.UseShellExecute = $false; $start.CreateNoWindow = $true
            $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
            $child = [Diagnostics.Process]::Start($start)
            $null = $child.Handle # Retain a handle before releasing the child's gate.
            $held += [pscustomobject]@{ operation=$operation; process=$child; gate=$gate; ready=$ready }
            if (!$ready.WaitOne(10000)) { throw "$operation did not acquire its earlier handle/mapping." }
        }
        & fltmc.exe load BdgDriver
        if ($LASTEXITCODE -ne 0) { throw 'Driver reload failed.' }
        Run-Probe 'read denied after reload' 2 @('read',$cookie)
        foreach ($entry in $held) {
            $entry.gate.Set() | Out-Null
            $finished = $entry.process.WaitForExit(10000)
            if ($finished) {
                $entry.process.StandardOutput.ReadToEnd() | Set-Content -LiteralPath (Join-Path $diagnostics "$($entry.operation).stdout.txt")
                $entry.process.StandardError.ReadToEnd() | Set-Content -LiteralPath (Join-Path $diagnostics "$($entry.operation).stderr.txt")
            }
            if (!$finished -or $entry.process.ExitCode -ne 0) { throw "$($entry.operation) failed: completed=$finished exit=$($entry.process.ExitCode)." }
        }
        & fltmc.exe unload BdgDriver
        if ($LASTEXITCODE -ne 0) { throw 'Final clean unload failed.' }
    } finally {
        foreach ($entry in $held) {
            if (!$entry.process.HasExited) { $entry.process.Kill(); $entry.process.WaitForExit() }
            $entry.process.Dispose(); $entry.gate.Dispose(); $entry.ready.Dispose()
        }
    }
    @{ vmId=$VmId.ToString(); unloadSucceeded=$true; readAfterUnload=0; readAfterReload=2; finalState='unloaded';
        knownGaps=@('pre-existing file handle remains readable','pre-existing mapping remains readable') } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $diagnostics 'recovery.json') -Encoding utf8
    return
}
if ($manifest.stage -ne 'catalog-signed') { throw 'Sign and verify the catalog before driver installation.' }
if (!(Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\BdgDriver')) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BdgLabDriverInstaller {
  [DllImport("newdev.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool DiInstallDriverW(IntPtr window, string infPath, uint flags,
    [MarshalAs(UnmanagedType.Bool)] out bool rebootRequired);
}
'@
    $rebootRequired = $false
    $installed = [BdgLabDriverInstaller]::DiInstallDriverW([IntPtr]::Zero,"$package\BdgDriver.inf",0,[ref]$rebootRequired)
    if (!$installed) { throw "DiInstallDriver failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    if ($rebootRequired) { throw 'Driver package requests a VM reboot before testing.' }
}
$serviceKey = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\BdgDriver'
$installedImage = [Environment]::ExpandEnvironmentVariables($serviceKey.ImagePath)
if ($installedImage.StartsWith('\SystemRoot\',[StringComparison]::OrdinalIgnoreCase)) { $installedImage = Join-Path $env:windir $installedImage.Substring(12) }
if ($installedImage.StartsWith('\??\')) { $installedImage = $installedImage.Substring(4) }
if (!(Test-Path -LiteralPath $installedImage) -or
    (Get-FileHash -LiteralPath $installedImage).Hash -ne (Get-FileHash -LiteralPath "$package\BdgDriver.sys").Hash) {
    throw 'Installed service image does not match the signed lab SYS.'
}
$instanceRoots = @('HKLM:\SYSTEM\CurrentControlSet\Services\BdgDriver\Instances',
    'HKLM:\SYSTEM\CurrentControlSet\Services\BdgDriver\Parameters\Instances') |
    Where-Object { Test-Path -LiteralPath $_ }
if (!$instanceRoots) { throw 'The driver package did not register any minifilter instance.' }
function Instance-Snapshot {
    $entries = @(foreach ($instanceRoot in $instanceRoots) {
        if (!(Test-Path -LiteralPath $instanceRoot)) { throw 'Configuration removed the minifilter instance registration.' }
        $keys = @((Get-Item -LiteralPath $instanceRoot)) + @(Get-ChildItem -LiteralPath $instanceRoot -Recurse)
        foreach ($key in $keys | Sort-Object Name) {
            [ordered]@{ key=$key.Name; defaultInstance=$key.GetValue('DefaultInstance'); altitude=$key.GetValue('Altitude'); flags=$key.GetValue('Flags') }
        }
    })
    return ConvertTo-Json -InputObject $entries -Compress
}
$before = Instance-Snapshot
foreach ($attempt in 1..2) {
    & "$PSScriptRoot\Configure-LabVm.ps1" -ServiceExe "$guest\bin\bdg-service.exe" -LabBase 'X:\BDG-Lab' -DisposableVm
    if ((Instance-Snapshot) -ne $before) { throw "Configuration attempt $attempt changed Filter Manager instance metadata." }
}
@{ instanceRegistrationPreserved=$true; repeatedConfigurationPreserved=$true } | ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $diagnostics 'configuration-preservation.json') -Encoding utf8
$filters = & fltmc.exe filters
if (!($filters | Where-Object { $_ -match '^BdgDriver\s' })) {
    $loadOutput = & fltmc.exe load BdgDriver 2>&1
    $loadCode = $LASTEXITCODE
    $loadOutput | Set-Content -LiteralPath (Join-Path $diagnostics 'driver-load.txt')
    if ($loadCode -ne 0) { throw "Driver load failed: exit=$loadCode; $($loadOutput -join ' ')" }
}
& fltmc.exe instances -f BdgDriver | Set-Content -LiteralPath (Join-Path $diagnostics 'instances.txt')
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate BDG instances.' }
Run-Verifier 'verifier-while-loaded' '/query' | Out-Null
& "$guest\bin\bdg-service.exe" --status | Set-Content -LiteralPath (Join-Path $diagnostics 'driver-status.txt')
if ($LASTEXITCODE -ne 0) { throw 'Driver reports no active protected instance.' }
$tag = Get-Date -Format 'yyyyMMdd-HHmmss'
$stdout = Join-Path $diagnostics "vm-tests-$tag.stdout.txt"
$stderr = Join-Path $diagnostics "vm-tests-$tag.stderr.txt"
$testProcess = Start-Process -FilePath "$guest\pwsh\pwsh.exe" -ArgumentList '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\BDG\repo\tests\Invoke-VmTests.ps1 -Binaries C:\BDG\bin -LabBase X:\BDG-Lab -DisposableVm' -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -Wait
if ($testProcess.ExitCode -ne 0) { throw "VM test suite failed: exit=$($testProcess.ExitCode). Logs: $diagnostics" }
Write-Output "VM test suite passed. Logs: $diagnostics"
