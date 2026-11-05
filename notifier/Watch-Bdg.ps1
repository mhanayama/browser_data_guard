[CmdletBinding()]
param([Parameter(Mandatory)][string]$LogPath)
$ErrorActionPreference = 'Stop'
Get-Content -LiteralPath $LogPath -Encoding utf8 -Wait | ForEach-Object {
    try {
        $entry = $_ | ConvertFrom-Json -ErrorAction Stop
        if ($entry.type -eq 'access') {
            $color = if ($entry.decision -eq 'deny') { 'Yellow' } else { 'Green' }
            Write-Host ("{0} {1} {2}/{3} {4} (PID {5})`n  {6}`n  -> {7} [flags={8}]" -f
                $entry.timestamp, $entry.decision.ToUpperInvariant(), $entry.browser, $entry.category,
                $entry.processName, $entry.pid, $entry.executablePath, $entry.target, $entry.flags) -ForegroundColor $color
        } elseif ($entry.type -eq 'audit_loss') {
            Write-Warning "Audit records lost (cumulative): $($entry.lostEvents)"
        } else { Write-Host $_ }
    } catch { Write-Warning "Unreadable log record: $($_.Exception.Message)" }
}
