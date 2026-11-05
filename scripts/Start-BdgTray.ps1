[CmdletBinding()]
param([string]$Log, [switch]$Background, [switch]$NoPopups, [switch]$TestAlert)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $repo 'out\notifier\Release\Bdg.Tray.exe'
if (!(Test-Path -LiteralPath $exe)) { throw 'Run scripts/Build-Notifier.ps1 first.' }
$state = Join-Path $repo 'out\tray-state'
New-Item -ItemType Directory -Path $state -Force | Out-Null
if (!$Log) {
    $installedLog = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'BrowserDataGuard\logs\events.jsonl'
    try { if (Test-Path -LiteralPath $installedLog) { $Log = $installedLog } } catch [UnauthorizedAccessException] { }
    if (!$Log) { $Log = Join-Path $state 'events.jsonl' }
}
$arguments = @('--state-dir', "`"$state`"", '--log', "`"$Log`"")
if ($Background) { $arguments += '--background' }
if ($TestAlert) { $arguments += '--test-alert' }
if ($NoPopups) { $arguments += '--no-popups' }
Start-Process -FilePath $exe -ArgumentList $arguments
