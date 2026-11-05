[CmdletBinding()]
param([string]$Executable = (Join-Path $PSScriptRoot '..\out\notifier\Release\Bdg.Tray.exe'))
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$state = Join-Path $repo ('out\testing\tray-smoke-' + [guid]::NewGuid().ToString('N'))
$resultPath = Join-Path $repo 'out\testing\tray-smoke-result.json'
New-Item -ItemType Directory -Path $state -Force | Out-Null
@{success=$false;stage='running';state=$state} | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding utf8
$log = Join-Path $state 'events.jsonl'
[IO.File]::WriteAllText($log, '')
$process = Start-Process -FilePath $Executable -ArgumentList @('--background','--no-popups','--run-seconds','10','--state-dir',"`"$state`"",'--log',"`"$log`"") -WindowStyle Hidden -PassThru
try {
    # Wait for the actual UI event loop, with no window shown and all popups disabled.
    $runtime = Join-Path $state 'runtime.json'
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while (!(Test-Path -LiteralPath $runtime)) {
        if ($process.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'Tray event loop did not start.' }
        Start-Sleep -Milliseconds 100
    }
    # Inject telemetry fixtures only, not an actual kernel denial. The test never opens a browser secret.
    $record = @{type='access';timestamp=[DateTimeOffset]::UtcNow.ToString('O');sequence=1;pid=0;
        processName='telemetry-fixture';executablePath='not-an-actual-process';target='C:\BDG-Lab\Protected\fixture.txt';
        browser='Synthetic';category='TestData';decision='deny'} | ConvertTo-Json -Compress
    [IO.File]::AppendAllText($log, $record + "`n", [Text.UTF8Encoding]::new($false))
    if (!$process.WaitForExit(25000)) { throw 'Tray did not exit after its command-line time limit.' }
    if ($process.ExitCode -ne 0) { throw "Tray failed: $($process.ExitCode)" }
    $result = Get-Content -LiteralPath $runtime -Raw | ConvertFrom-Json
    # Discovery is asynchronous and has separate fixture tests; game load must not make its
    # completion a prerequisite for notification responsiveness or a clean shutdown.
    if ($result.pid -ne $process.Id -or $result.ticks -lt 3 -or $result.popups -or $result.realDataProtected -or $result.labServiceAlive -or $result.denied -ne 1 -or $result.history -ne 1) {
        throw ('Unexpected tray state: ' + ($result | ConvertTo-Json -Compress))
    }
    [pscustomobject]@{success=$true;type='headless-telemetry-fixture';pid=$result.pid;uiTicks=$result.ticks;deniedFixtures=$result.denied;realDataProtected=$false;popups=$false;state=$state} |
        ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding utf8
    Write-Host 'Tray smoke passed: resident event loop, injected telemetry, no popups, clean timed exit.'
} finally {
    if (!$process.HasExited) { Stop-Process -Id $process.Id -Force }
    $process.Dispose()
}
