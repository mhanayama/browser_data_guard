[CmdletBinding()]
param([ValidateSet('Debug','Release')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$previousCli = $env:DOTNET_CLI_HOME
$previousNuget = $env:NUGET_PACKAGES
$previousFirstRun = $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE
$previousCert = $env:DOTNET_GENERATE_ASPNET_CERTIFICATE
try {
    $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
    $env:DOTNET_GENERATE_ASPNET_CERTIFICATE = 'false'
    $env:DOTNET_CLI_HOME = Join-Path $repo 'out\dotnet-home'
    $env:NUGET_PACKAGES = Join-Path $repo 'out\nuget'
    $project = Join-Path $repo 'notifier\Bdg.Tray.csproj'
    $output = Join-Path $repo "out\notifier\$Configuration"
    & dotnet build $project -c $Configuration -o $output --ignore-failed-sources -p:NuGetAudit=false
    if ($LASTEXITCODE -ne 0) { throw 'Notifier build failed.' }
    & dotnet (Join-Path $output 'Bdg.Tray.dll') --self-test
    if ($LASTEXITCODE -ne 0) { throw 'Notifier tests failed.' }
} finally {
    $env:DOTNET_CLI_HOME = $previousCli
    $env:NUGET_PACKAGES = $previousNuget
    $env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = $previousFirstRun
    $env:DOTNET_GENERATE_ASPNET_CERTIFICATE = $previousCert
}
