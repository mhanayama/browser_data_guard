#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binaries,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\BDG-Lab$')][string]$LabBase,
    [Parameter(Mandatory)][switch]$DisposableVm
)
$ErrorActionPreference = 'Stop'
if (!$DisposableVm) { throw 'Run only in a disposable Windows 11 VM with synthetic fixtures.' }
if ((Get-Content -LiteralPath (Join-Path $LabBase '.bdg-lab-fixture') -Raw) -ne 'bdg-synthetic-fixture-v1') { throw 'Invalid fixture marker.' }
$probe = (Resolve-Path -LiteralPath (Join-Path $Binaries 'bdg-probe.exe')).Path
$service = (Resolve-Path -LiteralPath (Join-Path $Binaries 'bdg-service.exe')).Path
$cookie = Join-Path $LabBase 'Protected\Chrome\Default\Network\Cookies'
$results = [Collections.Generic.List[object]]::new()
$children = [Collections.Generic.List[Diagnostics.Process]]::new()
$events = [Collections.Generic.List[IDisposable]]::new()
function Record([string]$Name, [bool]$Pass, [string]$Detail) {
    $results.Add([pscustomobject]@{ name=$Name; passed=$Pass; detail=$Detail })
    if (!$Pass) { throw "FAIL: $Name ($Detail)" }
}
function Spawn([string]$File, [string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($File)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    foreach ($arg in $Arguments) { $start.ArgumentList.Add($arg) }
    $child = [Diagnostics.Process]::Start($start)
    $children.Add($child)
    return $child
}
function Probe([string]$Name, [int]$Expected, [string[]]$Arguments) {
    & $probe @Arguments | Out-Host
    Record $Name ($LASTEXITCODE -eq $Expected) "exit=$LASTEXITCODE expected=$Expected"
}
function Wait-Ready([string]$Log, [Diagnostics.Process]$Child) {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        if ($Child.HasExited) { throw "Collector exited: $($Child.ExitCode)" }
        if ((Test-Path -LiteralPath $Log) -and (Select-String -LiteralPath $Log -Pattern '"type":"status"' -Quiet)) { return }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Collector did not become ready.'
}
try {
    & $service --status
    Record 'attached instance' ($LASTEXITCODE -eq 0) 'Service must be stopped before this single-port test.'
    Probe 'deny read' 2 @('read',$cookie)
    Probe 'deny copy' 2 @('copy',$cookie,(Join-Path $LabBase 'stolen-copy'))
    Probe 'deny new mapping' 2 @('map',$cookie)
    Probe 'deny MAXIMUM_ALLOWED' 2 @('max-allowed',$cookie)
    Probe 'deny valid truncate request' 2 @('truncate',$cookie)
    Probe 'deny write' 2 @('write',$cookie)
    Probe 'deny delete' 2 @('delete',$cookie)
    Probe 'deny new rename handle' 2 @('rename',$cookie,(Join-Path $LabBase 'renamed-cookie'))
    Probe 'allow metadata' 0 @('metadata',$cookie)
    Probe 'allow unrelated sibling' 0 @('read',(Join-Path $LabBase 'ProtectedSibling\ordinary.txt'))
    foreach ($relative in @('Chrome\Profile 1\Network\Cookies','Edge\Profile 2\Network\Cookies',
        'Firefox\profile-b\cookies.sqlite','Chrome\Default\Network\Cookies-wal',
        'Chrome\Default\Network\Cookies-shm','Chrome\Default\Network\Cookies-journal',
        'Chrome\Default\Local Storage\leveldb\000001.log','Chrome\Local State',
        'Firefox\profile-a\storage\default\https+++example.invalid\ls\data.sqlite')) {
        Probe "deny synthetic $relative" 2 @('read',(Join-Path $LabBase "Protected\$relative"))
    }
    $parallel = 1..8 | ForEach-Object { Spawn $probe @('read',$cookie) }
    foreach ($child in $parallel) {
        if (!$child.WaitForExit(15000)) { throw 'Concurrent read timed out.' }
        Record 'concurrent denial' ($child.ExitCode -eq 2) "exit=$($child.ExitCode)"
    }
    # This MUST remain labelled a known gap, not a protection pass.
    Probe 'KNOWN GAP: pre-existing outside hard link readable' 0 @('read',(Join-Path $LabBase 'outside-cookie-link'))

    $tag = [Guid]::NewGuid().ToString('N')
    $gateName = "Local\BDG-Gate-$tag"; $readyName = "Local\BDG-Ready-$tag"
    $gate = [Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$gateName)
    $ready = [Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$readyName)
    $events.Add($gate); $events.Add($ready)
    $trusted = Spawn $probe @('--gate',$gateName,'--ready',$readyName,'read',$cookie)
    if (!$ready.WaitOne(10000)) { throw 'Trusted probe did not reach its gate.' }
    $hash = (Get-FileHash -LiteralPath $probe -Algorithm SHA256).Hash
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $log = Join-Path $LabBase "events-$tag.jsonl"
    $collector = Spawn $service @('--console','--log',$log,'--trust-pid',"$($trusted.Id)",
        '--image',$probe,'--sha256',$hash,'--owner-sid',$owner,'--allow-unsigned-lab','--run-seconds','120')
    Wait-Ready $log $collector
    Probe 'same executable different process still denied' 2 @('read',$cookie)
    $gate.Set() | Out-Null
    if (!$trusted.WaitForExit(10000)) { throw 'Trusted read timed out.' }
    Record 'designated process allowed' ($trusted.ExitCode -eq 0) "exit=$($trusted.ExitCode)"
    $auditDeadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $records = @(Get-Content -LiteralPath $log | ForEach-Object { $_ | ConvertFrom-Json })
        if (@($records | Where-Object { $_.type -eq 'access' -and $_.decision -eq 'allow' }).Count) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $auditDeadline)
    Record 'denial audit delivered' (@($records | Where-Object { $_.type -eq 'access' -and $_.decision -eq 'deny' -and $_.executablePath }).Count -gt 0) $log
    Record 'allow audit delivered' (@($records | Where-Object { $_.type -eq 'access' -and $_.decision -eq 'allow' }).Count -gt 0) $log
    $collector.Kill(); $collector.WaitForExit()
    Probe 'service crash retains denial' 2 @('read',$cookie)
    $restartLog = Join-Path $LabBase "restart-$tag.jsonl"
    $restarted = Spawn $service @('--console','--log',$restartLog,'--run-seconds','120')
    Wait-Ready $restartLog $restarted
    Probe 'service restart retains denial' 2 @('read',$cookie)
    $restarted.Kill(); $restarted.WaitForExit()

    $beforeFlood = & $service --status
    if ($LASTEXITCODE -ne 0 -or ($beforeFlood -join ' ') -notmatch 'lost=(\d+)') { throw 'Cannot obtain the pre-flood loss counter.' }
    $lostBefore = [long]$Matches[1]
    foreach ($batch in 1..12) {
        $flood = @(1..8 | ForEach-Object { Spawn $probe @('read',$cookie) })
        foreach ($child in $flood) {
            if (!$child.WaitForExit(10000) -or $child.ExitCode -ne 2) { throw 'Audit overload changed denial behavior or hung a probe.' }
        }
    }
    Record '96 denials continue with no collector and a full audit queue' $true 'All flood probes returned access denied.'
    $afterFlood = & $service --status
    if ($LASTEXITCODE -ne 0 -or ($afterFlood -join ' ') -notmatch 'lost=(\d+)') { throw 'Cannot obtain the post-flood loss counter.' }
    $lostAfter = [long]$Matches[1]
    Record 'audit overflow is counted' ($lostAfter -gt $lostBefore) "lostBefore=$lostBefore lostAfter=$lostAfter"
    $lossLog = Join-Path $LabBase "audit-loss-$tag.jsonl"
    $lossCollector = Spawn $service @('--console','--log',$lossLog,'--run-seconds','120')
    Wait-Ready $lossLog $lossCollector
    $lossDeadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $lossRecords = @(Get-Content -LiteralPath $lossLog | ForEach-Object { $_ | ConvertFrom-Json })
        if (@($lossRecords | Where-Object { $_.type -eq 'audit_loss' -and $_.lostEvents -ge $lostAfter }).Count) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $lossDeadline)
    Record 'audit loss is visible to the collector' (@($lossRecords | Where-Object { $_.type -eq 'audit_loss' -and $_.lostEvents -ge $lostAfter }).Count -gt 0) $lossLog
    $lossCollector.Kill(); $lossCollector.WaitForExit()

    $gate.Reset() | Out-Null; $ready.Reset() | Out-Null
    $candidate = Spawn $probe @('--gate',$gateName,'--ready',$readyName,'read',$cookie)
    if (!$ready.WaitOne(10000)) { throw 'Candidate gate timeout.' }
    & $service --console --log (Join-Path $LabBase "bad-hash-$tag.jsonl") --trust-pid $candidate.Id --image $probe --sha256 ('0' * 64) --owner-sid $owner --allow-unsigned-lab --run-seconds 1
    Record 'changed image hash rejected' ($LASTEXITCODE -eq 1) 'Simulated stale pin after update; no trust granted.'
    $gate.Set() | Out-Null
    if (!$candidate.WaitForExit(10000)) { throw 'Candidate read timed out.' }
    Record 'failed verification leaves process denied' ($candidate.ExitCode -eq 2) "exit=$($candidate.ExitCode)"
} finally {
    foreach ($child in $children) { if (!$child.HasExited) { $child.Kill(); $child.WaitForExit() }; $child.Dispose() }
    foreach ($event in $events) { $event.Dispose() }
    $results | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $LabBase 'vm-results.json') -Encoding utf8
}
Write-Output "VM synthetic tests complete. Driver remains loaded. Results: $LabBase\vm-results.json"
