[CmdletBinding()]
param([Parameter(Mandatory)][string]$Executable)
$ErrorActionPreference = 'Stop'
# Independent Windows hash implementation supplies the pin to the identity test.
$pin = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
& $Executable $pin
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
