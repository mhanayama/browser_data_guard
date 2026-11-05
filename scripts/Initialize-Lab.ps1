[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\$')][string]$VolumeRoot)
$ErrorActionPreference = 'Stop'
$volume = Get-Volume -DriveLetter $VolumeRoot.Substring(0,1)
if ($volume.FileSystem -ne 'NTFS' -or $volume.DriveType -ne 'Fixed') { throw 'Use a local fixed NTFS volume in a disposable VM.' }
$lab = Join-Path $VolumeRoot 'BDG-Lab'
if (Test-Path -LiteralPath $lab) { throw 'BDG-Lab already exists. Use a fresh VM snapshot; this script never overwrites a lab.' }
New-Item -ItemType Directory -Path $lab | Out-Null
$files = @(
    'Chrome\Default\Network\Cookies', 'Chrome\Profile 1\Network\Cookies',
    'Edge\Default\Network\Cookies', 'Edge\Profile 2\Network\Cookies',
    'Firefox\profile-a\cookies.sqlite', 'Firefox\profile-b\cookies.sqlite',
    'Chrome\Local State', 'Edge\Local State',
    'Chrome\Default\Local Storage\leveldb\000001.log',
    'Edge\Default\Local Storage\leveldb\CURRENT',
    'Firefox\profile-a\storage\default\https+++example.invalid\ls\data.sqlite'
)
$protected = Join-Path $lab 'Protected'
foreach ($relative in $files) {
    $target = Join-Path $protected $relative
    New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
    [IO.File]::WriteAllText($target, 'SYNTHETIC BDG TEST DATA - NOT A REAL DATABASE')
    if ($target.EndsWith('Cookies') -or $target.EndsWith('.sqlite')) {
        foreach ($suffix in @('-wal','-shm','-journal')) { [IO.File]::WriteAllText($target + $suffix, 'SYNTHETIC SQLITE COMPANION') }
    }
}
$sibling = Join-Path $lab 'ProtectedSibling'
New-Item -ItemType Directory -Path $sibling | Out-Null
[IO.File]::WriteAllText((Join-Path $sibling 'ordinary.txt'), 'UNPROTECTED FIXTURE')
[IO.File]::WriteAllText((Join-Path $lab '.bdg-lab-fixture'), 'bdg-synthetic-fixture-v1')
# An intentionally outside alias demonstrates the documented path-only bypass.
New-Item -ItemType HardLink -Path (Join-Path $lab 'outside-cookie-link') -Target (Join-Path $protected 'Chrome\Default\Network\Cookies') | Out-Null
Write-Output "Created synthetic fixtures only: $lab"
