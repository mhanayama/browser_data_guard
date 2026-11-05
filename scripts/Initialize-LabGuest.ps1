#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][guid]$VmId)
$ErrorActionPreference = 'Stop'
$guest = 'C:\BDG'
if ($env:COMPUTERNAME -ne 'BDG-LAB' -or (Get-CimInstance Win32_ComputerSystem).Model -ne 'Virtual Machine' -or
    (Get-Content -LiteralPath "$guest\.bdg-disposable-vm" -Raw).Trim() -ne $VmId.ToString()) {
    throw 'This script can run only inside the newly created, marked BDG lab VM.'
}
$redist = Start-Process -FilePath "$guest\vc_redist.x64.exe" -ArgumentList '/install /quiet /norestart' -WindowStyle Hidden -PassThru -Wait
if ($redist.ExitCode -notin @(0,3010,1638)) { throw "VC runtime installation failed: $($redist.ExitCode)" }
$raw = @(Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' -and $_.Size -eq 8GB -and !$_.IsBoot -and !$_.IsSystem })
if ($raw.Count -ne 1 -or (Get-Volume -DriveLetter X -ErrorAction SilentlyContinue)) { throw 'Expected one empty 8 GiB virtual test disk and an unused X:.' }
$raw[0] | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -DriveLetter X |
    Format-Volume -FileSystem NTFS -NewFileSystemLabel 'BDG-Test' -Confirm:$false | Out-Null
& "$PSScriptRoot\Initialize-Lab.ps1" -VolumeRoot 'X:\'

$package = "$guest\package"
if (Test-Path -LiteralPath $package) { throw 'Package already exists; restore a clean VM checkpoint.' }
New-Item -ItemType Directory -Path $package | Out-Null
$altitude = '89999.9001'
$filters = & fltmc.exe filters
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate VM filters.' }
if ($filters -match '\s89999\.9001\s') { throw 'The isolated lab altitude is already in use.' }
$filters | Set-Content -LiteralPath "$guest\filters-before.txt"
$template = Get-Content -LiteralPath "$guest\BdgDriver.inf.in" -Raw
[IO.File]::WriteAllText("$package\BdgDriver.inf",$template.Replace('@BDG_TEST_ALTITUDE@',$altitude),[Text.Encoding]::ASCII)
Copy-Item -LiteralPath "$guest\BdgDriver.sys" -Destination $package
$certificate = New-SelfSignedCertificate -Subject "CN=BDG Disposable VM $($VmId.ToString().Substring(0,8))" `
    -Type CodeSigningCert -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable `
    -CertStoreLocation 'Cert:\LocalMachine\My' -NotAfter (Get-Date).AddDays(30)
$publicCertificate = "$guest\bdg-lab.cer"
Export-Certificate -Cert $certificate -FilePath $publicCertificate | Out-Null
Import-Certificate -FilePath $publicCertificate -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Import-Certificate -FilePath $publicCertificate -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
& "$guest\signtool.exe" sign /v /sm /s My /sha1 $certificate.Thumbprint /fd SHA256 "$package\BdgDriver.sys"
if ($LASTEXITCODE -ne 0) { throw 'Guest SYS signing failed.' }
& "$guest\signtool.exe" verify /v /pa "$package\BdgDriver.sys"
if ($LASTEXITCODE -ne 0) { throw 'Guest SYS signature verification failed.' }
[ordered]@{ vmId=$VmId.ToString(); package=$package; certificateThumbprint=$certificate.Thumbprint;
    testAltitude=$altitude; osVersion=[Environment]::OSVersion.Version.ToString(); stage='sys-signed'; runtimeExitCode=$redist.ExitCode } |
    ConvertTo-Json | Set-Content -LiteralPath "$guest\guest-manifest.json" -Encoding utf8
& bcdedit.exe /enum '{current}' | Set-Content -LiteralPath "$guest\guest-boot-config.txt"
# Remove the answer file and one-time auto-logon secret after successful first boot.
Remove-Item -LiteralPath 'C:\Windows\Panther\unattend.xml' -ErrorAction SilentlyContinue
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty -LiteralPath $winlogon -Name AutoAdminLogon -Value '0'
Remove-ItemProperty -LiteralPath $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
Write-Output "Guest fixtures and signed SYS prepared. VM: $VmId"
