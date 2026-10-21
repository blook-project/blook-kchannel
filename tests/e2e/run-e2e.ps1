<#
.SYNOPSIS
    Full blook-kchannel VM e2e: build, sign test drivers, run the guest matrix
    through bvmenv, run the deliberate-BSOD harness, and collect evidence.

.DESCRIPTION
    Requires:
      * xmake + WDK on the host (for the .sys build and signtool),
      * bvmenv.exe (blook-vmware-environment) with a base VM that already has
        test signing enabled,
      * a "vm-kchannel" (or -Vm) fork of that base image.

    A self-signed code-signing certificate named CN=blook-kchannel-test is
    created in the *current user* certificate store on first use (no private
    key is committed to the repo) and its .cer is pushed into the guest for
    the trusted root/publisher stores.

.EXAMPLE
    pwsh tests/e2e/run-e2e.ps1
    pwsh tests/e2e/run-e2e.ps1 -Vm vm-kchannel -Out docs/evidence/20261021-vm-e2e
#>
[CmdletBinding()]
param(
    [string]$Vm = 'vm-kchannel',
    [string]$Out,
    [string]$Bvmenv,
    [string]$SignTool,
    [switch]$SkipBuild,
    [switch]$SkipCrashRun,
    [switch]$PrepareOnly
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# HOST SAFETY: the orchestrator only builds/signs and drives bvmenv; it never
# loads a driver itself. It must run on the physical host, not inside a guest.
# ---------------------------------------------------------------------------
if (Test-Path 'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools') {
    throw 'REFUSING to run: the e2e orchestrator must run on the host, not inside a VMware guest'
}
if (-not $Vm) {
    throw 'REFUSING to run: pass -Vm <name> (a bvmenv VM fork created from the base snapshot)'
}
Write-Host "host safety: no driver is loaded on this host; all kernel code runs in VM '$Vm'"
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$version = (Get-Content (Join-Path $repo 'version.txt') -Raw).Trim()
if (-not $Out) {
    $Out = Join-Path $repo ("docs/evidence/" + (Get-Date -Format 'yyyyMMdd') + '-vm-e2e')
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null

function Find-Bvmenv {
    if ($Bvmenv) { return (Resolve-Path $Bvmenv).Path }
    $fromPath = Get-Command bvmenv.exe -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    foreach ($candidate in @(
        'D:\blook-kernel-project\blook-vmware-environment\build\windows\x64\release\bvmenv.exe',
        'D:\blook-kernel-project\blook-vmware-environment\build\windows\x64\releasedbg\bvmenv.exe')) {
        if (Test-Path $candidate) { return $candidate }
    }
    throw 'bvmenv.exe not found: pass -Bvmenv or put it on PATH'
}

function Find-SignTool {
    if ($SignTool) { return (Resolve-Path $SignTool).Path }
    $roots = @(
        'C:\Program Files (x86)\Windows Kits\10\bin',
        'Y:\Program Files (x86)\Windows Kits\10\bin',
        'D:\Program Files (x86)\Windows Kits\10\bin'
    ) | Where-Object { Test-Path $_ }
    $candidate = $null
    foreach ($root in $roots) {
        if ($candidate) { break }
        $candidate = Get-ChildItem $root -Directory |
            Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName 'x64\signtool.exe' } |
            Where-Object { Test-Path $_ } |
            Select-Object -First 1
    }
    if (-not $candidate) { throw 'signtool.exe not found: pass -SignTool' }
    return $candidate
}

function Get-TestCertificate {
    $existing = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq 'CN=blook-kchannel-test' } |
        Select-Object -First 1
    if ($existing) { return $existing }
    Write-Host 'creating test code-signing certificate CN=blook-kchannel-test (CurrentUser\My)'
    return New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject 'CN=blook-kchannel-test' `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyUsage DigitalSignature `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')
}

function Invoke-Bvmenv {
    param([string[]]$Arguments)
    $output = & $bv @Arguments 2>&1
    $exit = $LASTEXITCODE
    return [pscustomobject]@{ ExitCode = $exit; Output = ($output -join "`n") }
}

$bv = Find-Bvmenv
# SPC signing: real legacy Authenticode signature (no test signing required)
$signerScript = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'scripts/sign-driver.ps1'
$certificate = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -match 'XINDA' } | Select-Object -First 1
if ($null -eq $certificate) { throw 'XINDA SPC certificate not found in CurrentUser\My' }
$thumbprint = $certificate.Thumbprint
Write-Host "bvmenv:  $bv"
Write-Host "signtool: $signtool"
Write-Host "cert:     $thumbprint"

# ------------------------------- build -------------------------------
$release = Join-Path $repo 'build/windows/x64/release'
if (-not $SkipBuild) {
    Push-Location $repo
    try {
        & xmake f -y -m release | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'xmake configure failed' }
        & xmake -y
        if ($LASTEXITCODE -ne 0) { throw 'xmake build failed' }
        & xmake run kchannel-unit-tests 2>&1 | Tee-Object -FilePath (Join-Path $Out 'host-unit.txt')
        if ($LASTEXITCODE -ne 0) { throw 'host unit tests failed' }
    }
    finally { Pop-Location }
}

$driver = Join-Path $release 'kchannel_test.sys'
$mapper = Join-Path $release 'kcmapload.sys'
$ctl = Join-Path $release 'kchannel-ctl.exe'
foreach ($artifact in @($driver, $mapper, $ctl)) {
    if (-not (Test-Path $artifact)) { throw "missing build artifact: $artifact" }
}

# ------------------------------- sign --------------------------------
$signed = Join-Path $Out 'signed'
New-Item -ItemType Directory -Force -Path $signed | Out-Null
foreach ($file in @($driver, $mapper)) {
    Copy-Item $file (Join-Path $signed (Split-Path $file -Leaf)) -Force
}
& pwsh -NoProfile -File $signerScript -ImportTsaRoot -Sha1 -Driver ((Join-Path $signed 'kchannel_test.sys') + ',' + (Join-Path $signed 'kcmapload.sys'))
if ($LASTEXITCODE -ne 0) { throw 'SPC signing failed' }
Write-Host 'SPC-signed kchannel_test.sys and kcmapload.sys (legacy Authenticode)'
$cerPath = Join-Path $Out 'blook-kchannel-xinda.cer'
Export-Certificate -Cert $certificate -FilePath $cerPath -Type CERT | Out-Null
Copy-Item (Join-Path $repo 'signer\tsa\tsa-root.cer') $Out -Force
Copy-Item (Join-Path $repo 'signer\certs\verisign-cscs-2010.cer') $Out -Force
Copy-Item (Join-Path $repo 'signer\certs\verisign-g5-mcvr.cer') $Out -Force

# ------------------------- VM availability ---------------------------
$list = Invoke-Bvmenv @('list', '--json')
if ($list.ExitCode -ne 0) { throw "bvmenv list failed: $($list.Output)" }
$listJson = $list.Output | ConvertFrom-Json
if (-not ($listJson.vms | Where-Object { $_.name -eq $Vm })) {
    Write-Host "creating VM $Vm from base"
    $created = Invoke-Bvmenv @('create', $Vm, '--no-start')
    if ($created.ExitCode -ne 0) { throw "bvmenv create failed: $($created.Output)" }
} else {
    Write-Host "VM $Vm exists; start is idempotent, no reset (forks disappear during base refreshes)"
}
Write-Host "starting VM $Vm (idempotent)"
$startOut = Invoke-Bvmenv @('start', $Vm, '--no-wait')
Write-Host $startOut.Output

# --------------------------- main bundle -----------------------------
$bundle = Join-Path $Out 'bundle'
if (Test-Path $bundle) { Remove-Item $bundle -Recurse -Force }
New-Item -ItemType Directory -Force -Path $bundle | Out-Null
Copy-Item (Join-Path $signed 'kchannel_test.sys') $bundle -Force
Copy-Item (Join-Path $signed 'kcmapload.sys') $bundle -Force
Copy-Item $ctl $bundle -Force
Copy-Item $cerPath $bundle -Force
Copy-Item (Join-Path $Out 'tsa-root.cer') $bundle -Force
Copy-Item (Join-Path $Out 'verisign-cscs-2010.cer') $bundle -Force
Copy-Item (Join-Path $Out 'verisign-g5-mcvr.cer') $bundle -Force
Copy-Item (Join-Path $PSScriptRoot 'guest-run.ps1') $bundle -Force
@"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0guest-run.ps1"
exit /b %ERRORLEVEL%
"@ | Set-Content -Encoding ascii (Join-Path $bundle 'run-e2e.cmd')
@"
@echo off
set BVMENV_GUEST=1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0guest-run.ps1"
exit /b %ERRORLEVEL%
"@ | Set-Content -Encoding ascii (Join-Path $bundle 'run-guest-exec.cmd')

if ($PrepareOnly) {
    Write-Host 'prepare-only: build, tests, signing and bundle are ready'
    exit 0
}

Write-Host '--- running main e2e matrix ---'
$mainOut = Join-Path $Out 'main'
$mainRun = Invoke-Bvmenv @('e2e', $Vm, '--bundle', $bundle, '--entry', 'run-e2e.cmd',
    '--timeout', '1800', '--wait-timeout', '600', '--out', $mainOut,
    '--reset-on', 'never', '--env', 'BLOOK_VM_GUEST=$Vm',
    '--env', 'BLOOK_ALLOW_KERNEL_LOAD=1')
Write-Host $mainRun.Output
$mainResult = Get-ChildItem $mainOut -Recurse -Filter result.json | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($mainResult) {
    $mainJson = Get-Content $mainResult.FullName -Raw | ConvertFrom-Json
    # bvmenv's outcome only reflects the exec exit code; also require the guest
    # matrix itself to report zero failing checks and an ok:true summary.
    $mainRunDir = Split-Path $mainResult.FullName -Parent
    $stdoutFile = Join-Path $mainRunDir 'stdout.txt'
    if (Test-Path $stdoutFile) {
        $stdoutText = Get-Content $stdoutFile -Raw
        $failLines = ([regex]::Matches($stdoutText, '\[FAIL\]')).Count
        if ($failLines -gt 0) {
            Write-Host "guest matrix reported $failLines failing checks"
            $mainJson.outcome = 'fail-checks'
        }
        if ($stdoutText -notmatch '"ok":\s*true') {
            Write-Host 'guest summary missing ok:true'
            $mainJson.outcome = 'fail-summary'
        }
    } else {
        Write-Host "warning: no stdout.txt under $mainRunDir"
        $mainJson.outcome = 'fail-no-stdout'
    }
    Write-Host "main outcome: $($mainJson.outcome)"
} else {
    Write-Host 'warning: main result.json not found'
}

# --------------------------- crash bundle ----------------------------
if (-not $SkipCrashRun) {
    $crashBundle = Join-Path $Out 'crash-bundle'
    if (Test-Path $crashBundle) { Remove-Item $crashBundle -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $crashBundle | Out-Null
    Copy-Item (Join-Path $signed 'kchannel_test.sys') $crashBundle -Force
    Copy-Item $ctl $crashBundle -Force
    Copy-Item $cerPath $crashBundle -Force
    Copy-Item (Join-Path $Out 'tsa-root.cer') $crashBundle -Force
    Copy-Item (Join-Path $Out 'verisign-cscs-2010.cer') $crashBundle -Force
    Copy-Item (Join-Path $Out 'verisign-g5-mcvr.cer') $crashBundle -Force
    Copy-Item (Join-Path $PSScriptRoot 'crash-run.ps1') $crashBundle -Force
    @"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0crash-run.ps1"
exit /b %ERRORLEVEL%
"@ | Set-Content -Encoding ascii (Join-Path $crashBundle 'crash-run.cmd')
    @"
@echo off
set BVMENV_GUEST=1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0crash-run.ps1"
exit /b %ERRORLEVEL%
"@ | Set-Content -Encoding ascii (Join-Path $crashBundle 'run-crash-exec.cmd')
    Write-Host '--- running deliberate-BSOD harness ---'
    $crashOut = Join-Path $Out 'crash'
    $crashRun = Invoke-Bvmenv @('e2e', $Vm, '--bundle', $crashBundle, '--entry', 'crash-run.cmd',
        '--timeout', '900', '--wait-timeout', '600', '--out', $crashOut,
        '--reset-on', 'never', '--env', 'BLOOK_VM_GUEST=$Vm',
        '--env', 'BLOOK_ALLOW_KERNEL_LOAD=1')
    Write-Host $crashRun.Output
    $crashResultFile = Get-ChildItem $crashOut -Recurse -Filter result.json | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($crashResultFile) {
        $crashJson = Get-Content $crashResultFile.FullName -Raw | ConvertFrom-Json
        Write-Host "crash outcome: $($crashJson.outcome)"
    }
}
# ------------------------- metrics extraction ------------------------
# Pull every JSON object the guest printed out of the captured stdout so the
# evidence directory gets machine-readable numbers even though bvmenv does not
# pull the bundle back. render-performance.ps1 then refreshes docs/performance.md.
try {
$metricObjects = New-Object System.Collections.Generic.List[object]
$mainStdout = Get-ChildItem $mainOut -Recurse -Filter stdout.txt -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($mainStdout) {
    $text = Get-Content $mainStdout.FullName -Raw
    foreach ($match in [regex]::Matches($text, '\{[^\r\n]*\}')) {
        $candidate = $match.Value
        if ($candidate -notmatch '"median_ns"|"worker_cpu_percent"|"stop_ns"|"mapped_expectation"|"system_busy_percent"') {
            continue
        }
        try { $metricObjects.Add(($candidate | ConvertFrom-Json)) } catch { }
    }
}
$metricObjects.ToArray() | ConvertTo-Json -Depth 6 |
    Set-Content (Join-Path $Out 'metrics.json')
Write-Host "metrics: $($metricObjects.Count) objects -> metrics.json"
} catch {
    Write-Host "warning: metrics extraction failed: $($_.Exception.Message)"
}
$renderScript = Join-Path $PSScriptRoot 'render-performance.ps1'
if (Test-Path $renderScript) {
    & $renderScript -Evidence $Out -Doc (Join-Path $repo 'docs/performance.md')
}


# ---------------------------- summary --------------------------------
$summary = [ordered]@{
    schema       = 'blook-kchannel.e2e.v1'
    vm           = $Vm
    repo_commit  = (& git -C $repo rev-parse HEAD 2>$null)
    timestamp    = (Get-Date -Format o)
    version      = $version
    main_outcome = $(if ($mainJson) { $mainJson.outcome } else { 'missing' })
    crash_outcome = $(if ($crashJson) { $crashJson.outcome } else { 'missing' })
    evidence_dir = $Out
}
$summary | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Out 'result.json')
Write-Host ($summary | ConvertTo-Json -Depth 4)

if ($mainJson -and $mainJson.outcome -ne 'pass') {
    Write-Host 'main e2e matrix FAILED'
    exit 1
}
exit 0
