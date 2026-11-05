#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ServiceExe)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$scratch = Join-Path $repo ('out\testing\observe-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$watched = Join-Path $scratch 'watched'
$other = Join-Path $scratch 'watched-sibling'
New-Item -ItemType Directory -Path $watched,$other | Out-Null
$file = Join-Path $watched 'sample.txt'
$outside = Join-Path $other 'sample.txt'
[IO.File]::WriteAllText($file, 'ordinary ETW test fixture')
[IO.File]::WriteAllText($outside, 'outside the selected subtree')
$policy = Join-Path $scratch 'policy.tsv'
[IO.File]::WriteAllText($policy, "BDG-OBSERVE-1`ntree`tFixture`tTestData`t$watched`n", [Text.UTF8Encoding]::new($false))
$log = Join-Path $scratch 'events.jsonl'
$process = Start-Process -FilePath $ServiceExe -ArgumentList @('--console','--observe','--policy',"`"$policy`"",'--log',"`"$log`"",'--run-seconds','10') -WindowStyle Hidden -PassThru -RedirectStandardError (Join-Path $scratch 'stderr.txt') -RedirectStandardOutput (Join-Path $scratch 'stdout.txt')
$retainedHandle = $process.Handle # PS 5 needs an open handle to retain the eventual exit code.
try {
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (!(Test-Path -LiteralPath $log) -or !(Select-String -LiteralPath $log -Pattern 'observe-etw' -Quiet)) {
        if ($process.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw ('ETW did not start: ' + (Get-Content -LiteralPath (Join-Path $scratch 'stderr.txt') -Raw)) }
        Start-Sleep -Milliseconds 100
    }
    # Only these dummy files are opened. No browser database/auth/key contents are read.
    1..4 | ForEach-Object {
        [IO.File]::ReadAllText($file) | Out-Null
        [IO.File]::AppendAllText($file, '.')
        [IO.File]::ReadAllText($outside) | Out-Null
        Start-Sleep -Milliseconds 100
    }
    if (!$process.WaitForExit(20000)) { throw 'ETW collector failed to stop.' }
    if ($process.ExitCode -ne 0) { throw ('ETW collector failed: ' + (Get-Content -LiteralPath (Join-Path $scratch 'stderr.txt') -Raw)) }
    $records = @(Get-Content -LiteralPath $log | ForEach-Object { $_ | ConvertFrom-Json })
    $events = @($records | Where-Object type -eq 'access')
    if (!@($events | Where-Object {$_.operation -eq 'open' -and $_.pid -eq $PID}).Count -or
        !@($events | Where-Object {$_.operation -eq 'read' -and $_.pid -eq $PID}).Count -or
        !@($events | Where-Object {$_.operation -eq 'write' -and $_.pid -eq $PID}).Count) { throw 'Missing real open/read/write events or requester attribution.' }
    if (@($events | Where-Object {$_.target -like '*watched-sibling*' -or $_.decision -ne 'observe'}).Count) { throw 'Subtree boundary or observation-only contract failed.' }
    $heartbeat = @($records | Where-Object type -eq 'heartbeat')[-1]
    if ($heartbeat.lostEvents -ne 0 -or $heartbeat.decodeErrors -ne 0) { throw ('ETW errors in smoke test: ' + ($heartbeat | ConvertTo-Json -Compress)) }
    [pscustomobject]@{success=$true;fixtureOnly=$true;realOpen=$true;realRead=$true;realWrite=$true;processAttributed=$true;boundaryPassed=$true;enforcement=$false;events=$events.Count;state=$scratch} |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $repo 'out\testing\observe-smoke-result.json') -Encoding utf8
    Write-Output 'ETW smoke passed: real open/read/write, requester PID, subtree boundary, clean stop.'
} finally {
    if (!$process.HasExited) { Stop-Process -Id $process.Id -Force }
    $process.Dispose()
}
