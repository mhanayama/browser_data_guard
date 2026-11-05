[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ServiceExe,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z]:\\BDG-Lab$')][string]$LabBase,
    [Parameter(Mandatory)][switch]$DisposableVm
)
$ErrorActionPreference = 'Stop'
if (!$DisposableVm) { throw 'This configuration is only for a disposable Windows 11 VM.' }
if (!(Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\BdgDriver')) { throw 'Install the signed VM package first; no driver service exists.' }
if ((Get-Content -LiteralPath (Join-Path $LabBase '.bdg-lab-fixture') -Raw) -ne 'bdg-synthetic-fixture-v1') { throw 'Synthetic fixture marker is missing or invalid.' }
$ntRoot = & $ServiceExe --nt-path (Join-Path $LabBase 'Protected')
if ($LASTEXITCODE -ne 0 -or $ntRoot -notmatch '^\\Device\\HarddiskVolume[0-9]+\\BDG-Lab\\Protected$') { throw 'Root canonicalization failed.' }
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\BdgDriver\Parameters'
# Registry New-Item -Force replaces an existing key, including its Instances subtree.
# Preserve the Filter Manager registration installed by the INF.
if (!(Test-Path -LiteralPath $key)) { New-Item -Path $key | Out-Null }
New-ItemProperty -LiteralPath $key -Name SyntheticMode -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -LiteralPath $key -Name ProtectedRoot -PropertyType String -Value $ntRoot -Force | Out-Null
Write-Output "Configured $ntRoot. The driver has NOT been loaded. Follow docs/DEVELOPMENT.md inside the VM."
