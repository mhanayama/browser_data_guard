[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsRoot = if (Test-Path -LiteralPath $vswhere) { & $vswhere -latest -products '*' -property installationPath } else { $null }
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$versions = if (Test-Path -LiteralPath "$kits\Include") {
    @(Get-ChildItem -LiteralPath "$kits\Include" -Directory | Where-Object { $_.Name -match '^10\.\d+\.\d+\.\d+$' } | ForEach-Object {
        [ordered]@{ version = $_.Name; sdk = Test-Path -LiteralPath (Join-Path $_.FullName 'um\Windows.h');
            kernelHeaders = Test-Path -LiteralPath (Join-Path $_.FullName 'km\fltKernel.h');
            filterLibrary = Test-Path -LiteralPath "$kits\Lib\$($_.Name)\km\x64\FltMgr.lib" }
    })
} else { @() }
[ordered]@{
    osVersion = [Environment]::OSVersion.Version.ToString()
    visualStudio = $vsRoot
    msbuild = if ($vsRoot) { Test-Path -LiteralPath "$vsRoot\MSBuild\Current\Bin\MSBuild.exe" } else { $false }
    wdkToolset = if ($vsRoot) { Test-Path -LiteralPath "$vsRoot\MSBuild\Microsoft\VC\v170\Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0" } else { $false }
    kits = $versions
    cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source
} | ConvertTo-Json -Depth 5
