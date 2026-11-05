[CmdletBinding()]
param([ValidateSet('Debug','Release')][string]$Configuration = 'Debug', [switch]$Driver)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio Installer/vswhere is required.' }
$vsRoot = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vsRoot) { throw 'Install Visual Studio C++ desktop tools.' }
if ($Driver) {
    $wdkToolset = Join-Path $vsRoot 'MSBuild\Microsoft\VC\v170\Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0'
    if (!(Test-Path -LiteralPath $wdkToolset)) { throw 'WDK VS integration is missing; kernel compilation was not attempted.' }
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
    $matchingKits = @(Get-ChildItem -LiteralPath (Join-Path $kits 'Include') -Directory | Where-Object {
        (Test-Path -LiteralPath (Join-Path $_.FullName 'km\fltKernel.h')) -and
        (Test-Path -LiteralPath (Join-Path $_.FullName 'um\Windows.h')) -and
        (Test-Path -LiteralPath "$kits\Lib\$($_.Name)\km\x64\FltMgr.lib")
    } | Sort-Object { [version]$_.Name } -Descending)
    if (!$matchingKits.Count) { throw 'A matching SDK/WDK with kernel headers and x64 FltMgr.lib is required; kernel compilation was not attempted.' }
    $kitVersion = $matchingKits[0].Name
    & (Join-Path $vsRoot 'MSBuild\Current\Bin\MSBuild.exe') (Join-Path $repo 'driver\BdgDriver.vcxproj') /m /nr:false "/p:Configuration=$Configuration" /p:Platform=x64 "/p:WindowsTargetPlatformVersion=$kitVersion"
} else {
    & cmake -S $repo -B (Join-Path $repo 'out\user') -G 'Visual Studio 17 2022' -A x64
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }
    & cmake --build (Join-Path $repo 'out\user') --config $Configuration --parallel -- /nr:false
    if ($LASTEXITCODE -ne 0) { throw 'User-mode build failed.' }
    & ctest --test-dir (Join-Path $repo 'out\user') -C $Configuration --output-on-failure
}
if ($LASTEXITCODE -ne 0) { throw "Build/test failed: $LASTEXITCODE" }
