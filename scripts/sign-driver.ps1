# Sign a kernel driver with the blook SPC signer (the same prebuilt signer
# blook-drv ships). SPC-signed images load on stock Windows without test
# signing, which is what the VM e2e and the CI kernel-smoke job rely on.
#
# Local use (dev host with the XINDA certificate in CurrentUser\My):
#   pwsh scripts/sign-driver.ps1 -Driver build/windows/x64/release/kchannel_test.sys
#
# CI use: import signer/tsa/tsa-root.cer + the XINDA PFX first, then this script.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string[]]$Driver,
    [string]$Cert = 'XINDA',
    [string]$TsaTime = '2013-01-01T00:00:00Z',
    [switch]$Sha1,
    [switch]$ImportTsaRoot
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$signer = Join-Path $repo 'signer\spcsign\spcsign.exe'
if (-not (Test-Path -LiteralPath $signer)) {
    throw "SPC signer not found: $signer (copy signer/ from blook-drv)"
}
$chains = @(
    (Join-Path $repo 'signer\certs\verisign-cscs-2010.cer'),
    (Join-Path $repo 'signer\certs\verisign-g5-mcvr.cer')
)
foreach ($chain in $chains) {
    if (-not (Test-Path -LiteralPath $chain)) { throw "missing chain certificate: $chain" }
}

if ($ImportTsaRoot) {
    $tsaRoot = Join-Path $repo 'signer\tsa\tsa-root.cer'
    if (Test-Path -LiteralPath $tsaRoot) {
        & certutil -addstore -f root $tsaRoot | Out-Null
    }
}

$paths = @()
foreach ($item in $Driver) {
    foreach ($piece in ($item -split ",")) {
        $trimmed = $piece.Trim().Trim("`").Trim("'")
        if ($trimmed.Length -gt 0) { $paths += $trimmed }
    }
}

$failed = 0
foreach ($path in $paths) {
    $resolved = (Resolve-Path -LiteralPath $path).Path
    $arguments = @('sign', '--cert', $Cert, '--tsa-time', $TsaTime)
    if ($Sha1) { $arguments += '--sha1' }
    foreach ($chain in $chains) { $arguments += @('--chain', $chain) }
    $arguments += $resolved
    $output = & $signer @arguments 2>&1
    $code = $LASTEXITCODE
    foreach ($line in $output) { Write-Host ('  spcsign: ' + [string]$line) }
    if ($code -ne 0) {
        Write-Host "spcsign failed for $resolved (exit $code)"
        $failed++
        continue
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($null -eq $signature -or $signature.SignerCertificate -eq $null) {
        Write-Host "no signature after spcsign for $resolved"
        $failed++
        continue
    }
    Write-Host ("signed with SPC: " + $resolved + " (signer " + $signature.SignerCertificate.Subject + ")")
}
if ($failed -ne 0) { throw "$failed driver(s) failed SPC signing" }
