#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [Parameter(Mandatory)][ValidateSet('Status','Start','Initialize','Package','Checkpoint','RestoreBaseline','Run','Recover','Uninstall','EnableVerifier','DisableVerifier','Restart','Collect','Stop')][string]$Action,
    [ValidatePattern('^[A-Za-z0-9-]+$')][string]$Label = 'baseline'
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$base = Join-Path $repo 'out\vm'
$manifestFile = (Resolve-Path -LiteralPath $ManifestPath).Path
if (!$manifestFile.StartsWith($base + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Manifest must be inside this workspace VM directory.' }
$manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
if ($manifest.createdBy -ne 'BrowserDataGuard disposable lab' -or $manifest.name -notmatch '^BDG-Lab-') { throw 'Not a BDG-owned disposable VM manifest.' }
$root = [IO.Path]::GetFullPath($manifest.root)
if (!$root.StartsWith($base + '\',[StringComparison]::OrdinalIgnoreCase) -or (Split-Path $manifestFile -Parent) -ne $root) { throw 'VM root does not match its manifest.' }
$vm = Get-VM -Id ([guid]$manifest.id)
if ($vm.Name -ne $manifest.name) { throw 'VM identity mismatch.' }
foreach ($disk in Get-VMHardDiskDrive -VM $vm) {
    if (![IO.Path]::GetFullPath($disk.Path).StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'VM has a disk outside its dedicated lab directory.' }
}
$log = Join-Path $root 'host-actions.log'
function Log([string]$Message) { "$(Get-Date -Format o) $Message" | Add-Content -LiteralPath $log -Encoding utf8 }
Log "Starting $Action ($Label)."
if ($Action -eq 'Status') { $vm | Select-Object Name,State,Status,MemoryAssigned,Uptime; return }
if ($Action -eq 'Start') {
    if ($vm.State -eq 'Paused') { Resume-VM -VM $vm }
    elseif ($vm.State -in @('Off','Saved')) { Start-VM -VM $vm }
    elseif ($vm.State -ne 'Running') { throw "VM is in a transitional state: $($vm.State)" }
    Log 'Dedicated VM is running or resuming.'
    return
}
if ($Action -eq 'Checkpoint') {
    if (Get-VMSnapshot -VM $vm -Name 'BDG-before-driver' -ErrorAction SilentlyContinue) { throw 'Baseline checkpoint already exists.' }
    Checkpoint-VM -VM $vm -SnapshotName 'BDG-before-driver'
    Log 'Created baseline checkpoint before driver installation.'
    return
}
if ($Action -eq 'RestoreBaseline') {
    $snapshot = Get-VMSnapshot -VM $vm -Name 'BDG-before-driver'
    Restore-VMSnapshot -VMSnapshot $snapshot -Confirm:$false
    Log 'Restored the dedicated VM baseline checkpoint.'
    return
}
if ($Action -eq 'Stop' -or $Action -eq 'Restart') {
    Stop-VM -VM $vm -Confirm:$false
    if ($Action -eq 'Restart') { Start-VM -VM $vm }
    Log "$Action requested for the disposable guest only."
    return
}
if ($vm.State -ne 'Running') { throw "VM is $($vm.State); use the Start action before guest operations." }
$credential = Import-Clixml -LiteralPath $manifest.credentialPath
$session = $null
$deadline = [DateTime]::UtcNow.AddMinutes(12)
do {
    try {
        $session = New-PSSession -VMId $vm.Id -Credential $credential -ErrorAction Stop
    } catch {
        if ($_.Exception -is [Management.Automation.ParameterBindingException]) { throw }
        Log 'Waiting for guest setup / PowerShell Direct.'
        if ([DateTime]::UtcNow -ge $deadline) { throw }
        Start-Sleep -Seconds 10
    }
} until ($session)
try {
    Invoke-Command -Session $session -ArgumentList $vm.Id.ToString() -ScriptBlock {
        param($expectedId)
        if ($env:COMPUTERNAME -ne 'BDG-LAB' -or (Get-Content -LiteralPath 'C:\BDG\.bdg-disposable-vm' -Raw).Trim() -ne $expectedId) { throw 'Guest identity check failed.' }
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    }
    if ($Action -in @('Initialize','Run','Recover','Uninstall','EnableVerifier','DisableVerifier')) {
        foreach ($folder in @('scripts','tests')) {
            Copy-Item -ToSession $session -LiteralPath (Join-Path $repo $folder) -Destination 'C:\BDG\repo' -Recurse -Force
        }
        if ($Action -eq 'Initialize') {
            Invoke-Command -Session $session -ArgumentList $vm.Id.ToString() -ScriptBlock {
                param($id)
                & 'C:\BDG\repo\scripts\Initialize-LabGuest.ps1' -VmId ([guid]$id)
            }
        } else {
            Invoke-Command -Session $session -ArgumentList $vm.Id.ToString(),$Action -ScriptBlock {
                param($id,$operation)
                & 'C:\BDG\repo\scripts\Test-LabGuest.ps1' -VmId ([guid]$id) -Action $operation
            }
        }
    } elseif ($Action -eq 'Package') {
        $package = Join-Path $root 'package'
        New-Item -ItemType Directory -Path $package -Force | Out-Null
        foreach ($file in @('BdgDriver.sys','BdgDriver.inf')) { Copy-Item -FromSession $session -LiteralPath "C:\BDG\package\$file" -Destination $package -Force }
        Copy-Item -FromSession $session -LiteralPath 'C:\BDG\bdg-lab.cer' -Destination $package -Force
        & 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x86\Inf2Cat.exe' "/driver:$package" /os:10_GE_X64 /verbose
        if ($LASTEXITCODE -ne 0) { throw 'Inf2Cat failed for the signed guest SYS.' }
        Copy-Item -ToSession $session -LiteralPath (Join-Path $package 'BdgDriver.cat') -Destination 'C:\BDG\package' -Force
        Copy-Item -ToSession $session -LiteralPath (Join-Path $repo 'scripts\Test-LabGuest.ps1') -Destination 'C:\BDG\repo\scripts' -Force
        Invoke-Command -Session $session -ArgumentList $vm.Id.ToString() -ScriptBlock {
            param($id)
            & 'C:\BDG\repo\scripts\Test-LabGuest.ps1' -VmId ([guid]$id) -Action SignCatalog
        }
        Copy-Item -FromSession $session -LiteralPath 'C:\BDG\package\BdgDriver.cat' -Destination $package -Force
    } elseif ($Action -eq 'Collect') {
        $destination = Join-Path $root "results\$Label"
        if (Test-Path -LiteralPath $destination) { throw 'Results label already exists; evidence will not be overwritten.' }
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Invoke-Command -Session $session -ScriptBlock {
            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'} -MaxEvents 30 -ErrorAction SilentlyContinue |
                Select-Object TimeCreated,Id,LevelDisplayName,Message | ConvertTo-Json -Depth 4 |
                Set-Content -LiteralPath 'C:\BDG\diagnostics\code-integrity.json' -Encoding utf8
            Start-Process -FilePath "$env:windir\System32\verifier.exe" -ArgumentList '/query' -WindowStyle Hidden -Wait `
                -RedirectStandardOutput 'C:\BDG\diagnostics\verifier-query.txt' -RedirectStandardError 'C:\BDG\diagnostics\verifier-query.stderr.txt'
            & fltmc.exe filters | Set-Content -LiteralPath 'C:\BDG\diagnostics\filters-after.txt'
            & sc.exe qc BdgDriver | Set-Content -LiteralPath 'C:\BDG\diagnostics\driver-service.txt'
            & sc.exe query BdgDriver | Set-Content -LiteralPath 'C:\BDG\diagnostics\driver-service-state.txt'
            & bcdedit.exe /enum '{current}' | Set-Content -LiteralPath 'C:\BDG\diagnostics\boot-config.txt'
            Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\BdgDriver' -ErrorAction SilentlyContinue | Select-Object ImagePath,Start,Type | ConvertTo-Json |
                Set-Content -LiteralPath 'C:\BDG\diagnostics\service-registry.json'
            Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\BdgDriver' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{ key=$_.Name; properties=(Get-ItemProperty -LiteralPath $_.PSPath | Out-String) }
            } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath 'C:\BDG\diagnostics\driver-registry.json'
            Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
                Select-Object ProductName,EditionID,DisplayVersion,CurrentBuild,UBR | ConvertTo-Json |
                Set-Content -LiteralPath 'C:\BDG\diagnostics\os-version.json' -Encoding utf8
        }
        Copy-Item -FromSession $session -LiteralPath 'C:\BDG\diagnostics' -Destination $destination -Recurse
        foreach ($pattern in @('X:\BDG-Lab\*.json','X:\BDG-Lab\*.jsonl')) {
            Copy-Item -FromSession $session -Path $pattern -Destination $destination -ErrorAction SilentlyContinue
        }
        Copy-Item -FromSession $session -LiteralPath 'C:\BDG\guest-manifest.json' -Destination $destination
        Write-Output "Collected results: $destination"
    }
    Log "Completed $Action ($Label)."
} catch {
    Log "FAILED $Action : $($_.Exception.Message)"
    throw
} finally { if ($session) { Remove-PSSession $session } }
