[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DriverBinary,
    [Parameter(Mandatory)][ValidatePattern('^8[0-9]{4}(\.[0-9]+)?$')][string]$TestAltitude,
    [Parameter(Mandatory)][switch]$LabOnly
)
$ErrorActionPreference = 'Stop'
if (!$LabOnly) { throw 'Staging requires an explicit isolated-lab designation.' }
$repo = Split-Path $PSScriptRoot -Parent
$package = Join-Path $repo 'out\package'
New-Item -ItemType Directory -Path $package -Force | Out-Null
# Do not overwrite an already signed/catalogued package.
if (Get-ChildItem -LiteralPath $package -Force) { throw 'Package directory must be empty. Choose a fresh checkout/build directory.' }
$template = Get-Content -LiteralPath (Join-Path $repo 'driver\BdgDriver.inf.in') -Raw
[IO.File]::WriteAllText((Join-Path $package 'BdgDriver.inf'), $template.Replace('@BDG_TEST_ALTITUDE@', $TestAltitude), [Text.Encoding]::ASCII)
Copy-Item -LiteralPath $DriverBinary -Destination (Join-Path $package 'BdgDriver.sys')
Write-Output "Staged UNSIGNED lab package at $package. Test altitude $TestAltitude is not a Microsoft allocation."
