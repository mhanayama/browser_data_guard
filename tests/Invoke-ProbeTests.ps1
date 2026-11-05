#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ProbeExe,
    [Parameter(Mandatory)][string]$ScratchRoot
)
$ErrorActionPreference = 'Stop'
$probe = (Resolve-Path -LiteralPath $ProbeExe).Path
$runRoot = Join-Path ([IO.Path]::GetFullPath($ScratchRoot)) ([Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
$results = [Collections.Generic.List[object]]::new()
$children = [Collections.Generic.List[Diagnostics.Process]]::new()
$events = [Collections.Generic.List[IDisposable]]::new()
$restoreAcls = [Collections.Generic.List[object]]::new()
function Check([string]$Name, [bool]$Passed, [string]$Detail = '') {
    $results.Add([pscustomobject]@{ name=$Name; passed=$Passed; detail=$Detail })
    if (!$Passed) { throw "FAIL: $Name ($Detail)" }
}
function Start-Probe([string[]]$Arguments) {
    $start = [Diagnostics.ProcessStartInfo]::new($probe)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($arg in $Arguments) { $start.ArgumentList.Add($arg) }
    $child = [Diagnostics.Process]::Start($start)
    $children.Add($child)
    return $child
}
function Exit-Code([Diagnostics.Process]$Child) {
    if (!$Child.WaitForExit(10000)) { $Child.Kill(); $Child.WaitForExit(); throw 'Probe timed out.' }
    $stdout = $Child.StandardOutput.ReadToEnd()
    $stderr = $Child.StandardError.ReadToEnd()
    return [pscustomobject]@{ code=$Child.ExitCode; stdout=$stdout; stderr=$stderr }
}
function Probe([string]$Name, [int]$Expected, [string[]]$Arguments) {
    $reply = Exit-Code (Start-Probe $Arguments)
    Check $Name ($reply.code -eq $Expected) "exit=$($reply.code), expected=$Expected, stderr=$($reply.stderr.Trim())"
}
function Fixture([string]$Name) {
    $path = Join-Path $runRoot $Name
    [IO.File]::WriteAllText($path, 'SYNTHETIC BDG PROBE BASELINE')
    return $path
}
function Deny-Read([string]$Path) {
    $original = Get-Acl -LiteralPath $Path
    $restoreAcls.Add([pscustomobject]@{ path=$Path; acl=$original })
    $changed = Get-Acl -LiteralPath $Path
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid,
        [Security.AccessControl.FileSystemRights]::ReadData,
        [Security.AccessControl.AccessControlType]::Deny)
    $changed.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $changed
}
try {
    $fixture = Fixture 'read fixture with spaces.txt'
    Probe 'ordinary read' 0 @('read',$fixture)
    Probe 'ordinary mapping' 0 @('map',$fixture)
    Probe 'metadata-only access' 0 @('metadata',$fixture)
    Probe 'MAXIMUM_ALLOWED read' 0 @('max-allowed',$fixture)
    $copy = Join-Path $runRoot 'copy with spaces.txt'
    Probe 'copy baseline' 0 @('copy',$fixture,$copy)
    Check 'copy preserves bytes' ((Get-FileHash -LiteralPath $copy).Hash -eq (Get-FileHash -LiteralPath $fixture).Hash)
    $link = Join-Path $runRoot 'outside-link.txt'
    Probe 'hard link baseline' 0 @('hardlink',$fixture,$link)
    Probe 'hard link read baseline' 0 @('read',$link)
    $renamed = Join-Path $runRoot 'renamed.txt'
    Probe 'rename baseline' 0 @('rename',$copy,$renamed)
    Check 'rename moves source' (!(Test-Path -LiteralPath $copy) -and (Test-Path -LiteralPath $renamed))
    Probe 'write baseline' 0 @('write',$renamed)
    Check 'write changes first byte' ([IO.File]::ReadAllBytes($renamed)[0] -eq [byte][char]'X')
    Probe 'delete baseline' 0 @('delete',$renamed)
    Check 'delete removes target' (!(Test-Path -LiteralPath $renamed))
    Probe 'missing file is not access-denied' 1 @('read',(Join-Path $runRoot 'absent.txt'))
    $truncated = Fixture 'truncate.txt'
    Probe 'valid truncate baseline' 0 @('truncate',$truncated)
    Check 'valid truncate empties the file' ((Get-Item -LiteralPath $truncated).Length -eq 0)
    Probe 'zero-rights truncate is an API error, not a policy denial' 1 @('truncate-zero',$fixture)

    $denied = Fixture 'acl-denied.txt'
    Deny-Read $denied
    Probe 'ACL read denial classified correctly' 2 @('read',$denied)
    Probe 'ACL copy denial classified correctly' 2 @('copy',$denied,(Join-Path $runRoot 'denied-copy.txt'))
    Probe 'ACL mapping denial classified correctly' 2 @('map',$denied)
    Probe 'ACL metadata remains allowed' 0 @('metadata',$denied)

    foreach ($operation in @('hold-read','hold-map')) {
        $heldFile = Fixture "$operation.txt"
        $tag = [Guid]::NewGuid().ToString('N')
        $gateName = "Local\BdgProbeGate-$tag"
        $readyName = "Local\BdgProbeReady-$tag"
        $gate = [Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$gateName)
        $ready = [Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$readyName)
        $events.Add($gate); $events.Add($ready)
        $held = Start-Probe @('--gate',$gateName,'--ready',$readyName,$operation,$heldFile)
        Check "$operation acquires before gate" ($ready.WaitOne(10000))
        Deny-Read $heldFile
        Probe "$operation new ACL-denied open" 2 @('read',$heldFile)
        $gate.Set() | Out-Null
        $reply = Exit-Code $held
        Check "$operation retains earlier access" ($reply.code -eq 0) $reply.stderr.Trim()
    }
} finally {
    foreach ($child in $children) {
        if (!$child.HasExited) { $child.Kill(); $child.WaitForExit() }
        $child.Dispose()
    }
    foreach ($event in $events) { $event.Dispose() }
    foreach ($entry in $restoreAcls) { Set-Acl -LiteralPath $entry.path -AclObject $entry.acl }
    # Preserve small synthetic fixtures and results as evidence; never delete outside the test run.
    [ordered]@{ scope='user-mode probes only; no driver connection'; checks=@($results); fixtureRoot=$runRoot } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $runRoot 'results.json') -Encoding utf8
}
Write-Output "$($results.Count) native probe checks passed. No kernel enforcement tested. Evidence: $runRoot"
