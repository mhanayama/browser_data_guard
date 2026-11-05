#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('^S-1-5-21-[0-9-]+$')][string]$OwnerSid)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$result = Join-Path $repo 'out\testing\observe-install-result.json'
$transcript = Join-Path $repo 'out\testing\observe-install-transcript.txt'
Start-Transcript -Path $transcript -Force | Out-Null
try {
    $exe = Join-Path $repo 'out\user\Release\bdg-service.exe'
    $sourcePolicy = Join-Path $repo 'out\testing\host-observe-policy.tsv'
    if (!(Test-Path -LiteralPath $exe) -or !(Test-Path -LiteralPath $sourcePolicy)) { throw 'Build/export the observer first.' }
    & (Join-Path $repo 'tests\Test-ObserveAdmin.ps1') -ServiceExe $exe
    $install = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'BrowserDataGuard'))
    $marker = Join-Path $install 'observe-install.marker'
    for ($path = $install; $path; $path = Split-Path $path -Parent) {
        if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Install ancestors must not be reparse points.' }
    }
    if (Test-Path -LiteralPath $install) {
        $owner = (Get-Acl -LiteralPath $install).GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Existing install must be owned by SYSTEM or Administrators.' }
        if (@(Get-ChildItem -LiteralPath $install -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Reparse points are not allowed in the installation.' }
        if (!(Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw) -ne 'BDG-OBSERVE-1') { throw 'Existing install directory is not a BDG observer installation.' }
    } else { New-Item -ItemType Directory -Path $install | Out-Null }
    # SYSTEM/admin may write; the interactive owner can read telemetry, not replace service code.
    & icacls.exe $install /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*$($OwnerSid):(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not set install ACL.' }
    $destination = Join-Path $install 'bdg-service.exe'
    $existing = Get-CimInstance Win32_Service -Filter "Name='BdgMonitor'"
    if ($existing) {
        if ($existing.PathName -notlike ('"' + $destination + '" --service --observe *')) { throw 'BdgMonitor points at an unexpected executable.' }
        Stop-Service BdgMonitor -ErrorAction Stop
    }
    Copy-Item -LiteralPath $exe -Destination $destination -Force
    Copy-Item -LiteralPath $sourcePolicy -Destination (Join-Path $install 'observe-policy.tsv') -Force
    $sourceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\BrowserDataGuard'
    if ([Diagnostics.EventLog]::SourceExists('BrowserDataGuard')) {
        if (!(Test-Path -LiteralPath $sourceKey)) { throw 'BrowserDataGuard event source belongs to another Windows log.' }
        $oldMessageFile = (Get-ItemProperty -LiteralPath $sourceKey -Name EventMessageFile).EventMessageFile
        if ($oldMessageFile -ne $destination) { throw 'BrowserDataGuard event source has an unexpected message resource.' }
    } else {
        New-EventLog -LogName Application -Source BrowserDataGuard -MessageResourceFile $destination
    }
    New-ItemProperty -LiteralPath $sourceKey -Name TypesSupported -PropertyType DWord -Value 7 -Force | Out-Null
    [IO.File]::WriteAllText($marker, 'BDG-OBSERVE-1')
    $logs = Join-Path $install 'logs'
    if (!(Test-Path -LiteralPath $logs)) { New-Item -ItemType Directory -Path $logs | Out-Null }
    & icacls.exe $install /setowner '*S-1-5-32-544' /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not set installation ownership.' }
    $image = '"' + $destination + '" --service --observe --policy "' + (Join-Path $install 'observe-policy.tsv') + '" --log "' + (Join-Path $logs 'events.jsonl') + '"'
    if ($existing) {
        if ($existing.PathName -ne $image) { throw 'Existing observer command line differs; refusing to replace its configuration.' }
        Set-Service BdgMonitor -StartupType Manual
    } else {
        New-Service -Name BdgMonitor -BinaryPathName $image -StartupType Manual -DisplayName 'Browser Data Guard - observation only' -Description 'ETW file I/O observation for selected browser/credential paths. Does not block access.' | Out-Null
    }
    Start-Service BdgMonitor
    $service = Get-Service BdgMonitor
    if ($service.Status -ne 'Running') { throw 'Observer is not running.' }
    [pscustomobject]@{success=$true;service='BdgMonitor';status='Running';mode='observe-etw';enforcement=$false;install=$install;log=(Join-Path $logs 'events.jsonl');ownerSid=$OwnerSid} |
        ConvertTo-Json | Set-Content -LiteralPath $result -Encoding utf8
} catch {
    [pscustomobject]@{success=$false;error=$_.Exception.Message} | ConvertTo-Json | Set-Content -LiteralPath $result -Encoding utf8
    throw
} finally { Stop-Transcript | Out-Null }
