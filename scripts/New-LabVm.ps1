#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$IsoPath,
    [ValidatePattern('^BDG-Lab-[A-Za-z0-9-]+$')][string]$Name = 'BDG-Lab-Win11',
    [Parameter(Mandatory)][switch]$DisposableVm,
    [switch]$Start
)
$ErrorActionPreference = 'Stop'
if (!$DisposableVm) { throw 'Only a newly created disposable VM is supported.' }
$repo = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$vmBase = Join-Path $repo 'out\vm'
$vmRoot = [IO.Path]::GetFullPath((Join-Path $vmBase $Name))
if (!$vmRoot.StartsWith($vmBase + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid VM destination.' }
if (Test-Path -LiteralPath $vmRoot) { throw 'VM destination already exists; it will not be overwritten.' }
if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw 'VM name already exists; it will not be modified.' }
$iso = (Resolve-Path -LiteralPath $IsoPath).Path
$required = @('out\user\Release\bdg-service.exe','out\user\Release\bdg-probe.exe','out\driver\Release\BdgDriver.sys')
foreach ($relative in $required) { if (!(Test-Path -LiteralPath (Join-Path $repo $relative))) { throw "Build Release first: $relative" } }
$freeMemory = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB
if ($freeMemory -lt 6GB) { throw 'At least 6 GiB of free host memory is required for the 4 GiB lab VM.' }
if ((Get-PSDrive -Name ([IO.Path]::GetPathRoot($vmRoot).Substring(0,1))).Free -lt 50GB) { throw 'At least 50 GiB of free host storage is required.' }
New-Item -ItemType Directory -Path $vmRoot | Out-Null
$logPath = Join-Path $vmRoot 'provision.log'
function Log([string]$Message) { "$(Get-Date -Format o) $Message" | Add-Content -LiteralPath $logPath -Encoding utf8 }
$osVhd = Join-Path $vmRoot 'os.vhdx'
$dataVhd = Join-Path $vmRoot 'test-data.vhdx'
$mountedIso = $false
$mountedVhd = $false
function Assert-NewLabDisk([int]$Number) {
    $disk = Get-Disk -Number $Number
    $backing = Get-VHD -DiskNumber $Number
    if ($disk.IsBoot -or $disk.IsSystem -or [string]$disk.BusType -notin @('File Backed Virtual','FileBackedVirtual','15') -or
        [IO.Path]::GetFullPath($backing.Path) -ne $osVhd) { throw 'Refusing to partition/format a disk other than the newly created lab VHDX.' }
    return $disk
}
try {
    Log 'Mounting Microsoft evaluation media read-only.'
    $image = Get-DiskImage -ImagePath $iso
    if (!$image.Attached) { $image = Mount-DiskImage -ImagePath $iso -StorageType ISO -Access ReadOnly -PassThru; $mountedIso = $true }
    $isoVolume = $image | Get-Volume
    if (!$isoVolume.DriveLetter) { throw 'The mounted ISO has no drive letter.' }
    $isoRoot = "$($isoVolume.DriveLetter):\"
    $setupSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $isoRoot 'setup.exe')
    if ($setupSignature.Status -ne 'Valid' -or $setupSignature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw 'Microsoft setup.exe signature validation failed.'
    }
    $wim = Join-Path $isoRoot 'sources\install.wim'
    $windowsImages = @(Get-WindowsImage -ImagePath $wim)
    $selected = @($windowsImages | Where-Object { $_.ImageName -match 'Enterprise' -and $_.ImageName -notmatch ' N( |$)' })
    if ($selected.Count -ne 1) { throw 'Expected exactly one non-N Enterprise evaluation image.' }
    $imageIndex = $selected[0].ImageIndex
    Log "Using image index $imageIndex ($($selected[0].ImageName))."

    New-VHD -Path $osVhd -SizeBytes 64GB -Dynamic | Out-Null
    New-VHD -Path $dataVhd -SizeBytes 8GB -Dynamic | Out-Null
    $vm = New-VM -Name $Name -Generation 2 -MemoryStartupBytes 4GB -VHDPath $osVhd -Path $vmRoot
    Set-VM -VM $vm -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -CheckpointType Standard -AutomaticCheckpointsEnabled $false -Notes 'Disposable BDG synthetic test VM. No real browser data.'
    Set-VMProcessor -VM $vm -Count 2
    Set-VMMemory -VM $vm -DynamicMemoryEnabled $false
    Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
    Enable-VMTPM -VM $vm
    # Guest firmware only: test-signed kernel drivers require Secure Boot to be off.
    Set-VMFirmware -VM $vm -EnableSecureBoot Off
    Add-VMHardDiskDrive -VM $vm -Path $dataVhd
    # No virtual switch is connected. Management uses PowerShell Direct.

    $mounted = Mount-VHD -Path $osVhd -PassThru
    $mountedVhd = $true
    $disk = $mounted | Get-Disk
    $disk = Assert-NewLabDisk $disk.Number
    if ($disk.PartitionStyle -ne 'RAW') { throw 'The new VHDX is not empty; refusing initialization.' }
    $diskNumber = $disk.Number
    $letters = @('R','S','T','U','V','W','Y','Z' | Where-Object { !(Get-Volume -DriveLetter $_ -ErrorAction SilentlyContinue) })
    if ($letters.Count -lt 2) { throw 'Two unused temporary drive letters are required.' }
    Initialize-Disk -Number $diskNumber -PartitionStyle GPT | Out-Null
    Assert-NewLabDisk $diskNumber | Out-Null
    $efi = New-Partition -DiskNumber $diskNumber -Size 260MB -GptType '{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}' -DriveLetter $letters[0]
    $efi | Format-Volume -FileSystem FAT32 -NewFileSystemLabel 'BDG-EFI' -Confirm:$false | Out-Null
    New-Partition -DiskNumber $diskNumber -Size 16MB -GptType '{E3C9E316-0B5C-4DB8-817D-F92DF00215AE}' | Out-Null
    Assert-NewLabDisk $diskNumber | Out-Null
    $windows = New-Partition -DiskNumber $diskNumber -UseMaximumSize -DriveLetter $letters[1]
    $windows | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'BDG-OS' -Confirm:$false | Out-Null
    $osRoot = "$($windows.DriveLetter):\"
    $efiRoot = "$($efi.DriveLetter):\"
    if (!$windows.DriveLetter -or !$efi.DriveLetter -or $osRoot -eq "$env:SystemDrive\" -or $efiRoot -eq "$env:SystemDrive\") { throw 'Unsafe deployment volumes.' }
    Log 'Applying evaluation image to the new VHDX; no host partitions are changed.'
    Expand-WindowsImage -ImagePath $wim -Index $imageIndex -ApplyPath $osRoot -CheckIntegrity -LogPath (Join-Path $vmRoot 'dism.log') | Out-Null

    $private = Join-Path $vmRoot 'private'
    New-Item -ItemType Directory -Path $private | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User,
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
    }
    Set-Acl -LiteralPath $private -AclObject $acl
    $random = New-Object byte[] 24
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($random) } finally { $rng.Dispose() }
    $password = 'Bdg!' + [Convert]::ToBase64String($random)
    $credential = [Management.Automation.PSCredential]::new('BdgLabAdmin',(ConvertTo-SecureString $password -AsPlainText -Force))
    $credentialPath = Join-Path $private 'guest-credential.clixml'
    $credential | Export-Clixml -LiteralPath $credentialPath
    $xmlPassword = [Security.SecurityElement]::Escape($password)
    $unattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>BDG-LAB</ComputerName><TimeZone>Tokyo Standard Time</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>ja-JP</InputLocale><SystemLocale>ja-JP</SystemLocale><UILanguage>ja-JP</UILanguage><UserLocale>ja-JP</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE><HideEULAPage>true</HideEULAPage><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><ProtectYourPC>3</ProtectYourPC></OOBE>
      <UserAccounts><LocalAccounts><LocalAccount wcm:action="add"><Name>BdgLabAdmin</Name><DisplayName>BDG Lab Administrator</DisplayName><Group>Administrators</Group><Password><Value>$xmlPassword</Value><PlainText>true</PlainText></Password></LocalAccount></LocalAccounts></UserAccounts>
      <AutoLogon><Enabled>true</Enabled><LogonCount>1</LogonCount><Username>BdgLabAdmin</Username><Password><Value>$xmlPassword</Value><PlainText>true</PlainText></Password></AutoLogon>
    </component>
  </settings>
</unattend>
"@
    [xml]$unattend | Out-Null
    $answerPath = Join-Path $private 'unattend.xml'
    [IO.File]::WriteAllText($answerPath,$unattend,[Text.UTF8Encoding]::new($false))
    $panther = Join-Path $osRoot 'Windows\Panther'
    New-Item -ItemType Directory -Path $panther -Force | Out-Null
    Copy-Item -LiteralPath $answerPath -Destination (Join-Path $panther 'unattend.xml')

    $guestRoot = Join-Path $osRoot 'BDG'
    New-Item -ItemType Directory -Path (Join-Path $guestRoot 'repo') -Force | Out-Null
    foreach ($folder in @('scripts','tests','notifier','docs')) { Copy-Item -LiteralPath (Join-Path $repo $folder) -Destination (Join-Path $guestRoot 'repo') -Recurse }
    Copy-Item -LiteralPath (Join-Path $repo 'out\user\Release') -Destination (Join-Path $guestRoot 'bin') -Recurse
    Copy-Item -LiteralPath 'C:\Program Files\PowerShell\7' -Destination (Join-Path $guestRoot 'pwsh') -Recurse
    Copy-Item -LiteralPath (Join-Path $repo 'out\driver\Release\BdgDriver.sys') -Destination $guestRoot
    Copy-Item -LiteralPath (Join-Path $repo 'driver\BdgDriver.inf.in') -Destination $guestRoot
    Copy-Item -LiteralPath 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe' -Destination $guestRoot
    Copy-Item -LiteralPath 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Redist\MSVC\v143\vc_redist.x64.exe' -Destination $guestRoot
    [IO.File]::WriteAllText((Join-Path $guestRoot '.bdg-disposable-vm'),$vm.Id.ToString())

    Assert-NewLabDisk $diskNumber | Out-Null
    Log 'Creating boot files on the new VHDX EFI partition with an explicit /s target.'
    & bcdboot.exe (Join-Path $osRoot 'Windows') /s "$($efi.DriveLetter):" /f UEFI /v | Out-File -LiteralPath (Join-Path $vmRoot 'bcdboot.log')
    if ($LASTEXITCODE -ne 0) { throw 'BCDBoot failed for the new VHDX.' }
    $guestBcd = Join-Path $efiRoot 'EFI\Microsoft\Boot\BCD'
    if (!(Test-Path -LiteralPath $guestBcd)) { throw 'Guest BCD store not found.' }
    & bcdedit.exe /store $guestBcd /set '{default}' testsigning on | Out-File -LiteralPath (Join-Path $vmRoot 'guest-bcd.log')
    if ($LASTEXITCODE -ne 0) { throw 'Cannot enable test signing in the offline guest BCD.' }
    $manifest = [ordered]@{
        name=$Name; id=$vm.Id.ToString(); root=$vmRoot; osVhd=$osVhd; dataVhd=$dataVhd
        credentialPath=$credentialPath; iso=$iso; isoSha256=(Get-FileHash -LiteralPath $iso -Algorithm SHA256).Hash
        createdBy='BrowserDataGuard disposable lab'; imageName=$selected[0].ImageName; stage='image-applied'
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $vmRoot 'manifest.json') -Encoding utf8
    Log 'Image and isolated VM configuration complete. Host boot policy and certificate trust are unchanged.'
} catch {
    Log "FAILED: $($_.Exception.Message)"
    throw
} finally {
    if ($mountedVhd) { Dismount-VHD -Path $osVhd }
    if ($mountedIso) { Dismount-DiskImage -ImagePath $iso | Out-Null }
}
if ($Start) { Start-VM -Name $Name; Log 'VM started; awaiting guest setup and PowerShell Direct.' }
Write-Output "Created disposable VM $Name. Manifest: $vmRoot\manifest.json"
