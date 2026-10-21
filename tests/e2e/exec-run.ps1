<#
.SYNOPSIS
    bvmenv exec-based VM e2e for blook-kchannel.

.DESCRIPTION
    Why this exists: `bvmenv e2e` refuses to run until the guest reports an
    interactive "ready" desktop. Lab clones can sit at the logon UI (autologon
    flake) while guest ops already work through bvmenv's SYSTEM fallback. This
    runner uses the same bvmenv guest channel directly:

      push bundle -> exec run-guest-exec.cmd -> pull results -> state/screenshot

    Kernel code still only ever runs inside the VMware guest. Host-side safety
    is enforced by scripts/check-host-safety.ps1 and the guards in the guest
    scripts; nothing here loads a driver on the host.

    Produces docs/evidence/<date>-vm-e2e with:
      result.json (blook-kchannel.e2e.v1: outcomes, vm, commit)
      main-exec/  exec JSON + stdout/stderr + pulled results + state/screenshot
      crash-exec/ exec JSON + state/screenshot showing the BSOD
#>
[CmdletBinding()]
param(
    [string]$Vm = 'vm-kchannel',
    [string]$Out,
    [string]$Bvmenv,
    [switch]$SkipBuild,
    [switch]$SkipCrashRun
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$version = (Get-Content (Join-Path $repo 'version.txt') -Raw).Trim()
if (-not $Out) {
    $Out = Join-Path $repo ("docs/evidence/" + (Get-Date -Format 'yyyyMMdd') + '-vm-e2e')
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path

function Find-Bvmenv {
    if ($Bvmenv) { return (Resolve-Path $Bvmenv).Path }
    foreach ($candidate in @(
        'D:\blook-kernel-project\blook-vmware-environment\dist\bvmenv-latest.exe',
        'D:\blook-kernel-project\blook-vmware-environment\dist\bvmenv.exe',
        (Join-Path $repo 'build\bvmenv-stable.exe'),
        'D:\blook-kernel-project\blook-vmware-environment\build\windows\x64\release\bvmenv.exe')) {
        if (Test-Path $candidate) { return (Resolve-Path $candidate).Path }
    }
    $fromPath = Get-Command bvmenv.exe -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    throw 'bvmenv.exe not found: pass -Bvmenv'
}

function Invoke-Bvmenv {
    param([string[]]$Arguments)
    $output = & $bv @Arguments 2>&1
    $exit = $LASTEXITCODE
    return [pscustomobject]@{ ExitCode = $exit; Output = ($output -join "`n") }
}

function Save-ExecArtifacts {
    param([string]$Directory, [object]$ExecResult, [string]$Label)
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $ExecResult.Output | Set-Content (Join-Path $Directory 'exec.json')
    $json = $null
    try { $json = $ExecResult.Output | ConvertFrom-Json } catch { }
    if ($json) {
        if ($json.stdout_tail) { $json.stdout_tail | Set-Content (Join-Path $Directory 'stdout.txt') }
        if ($json.stderr_tail) { $json.stderr_tail | Set-Content (Join-Path $Directory 'stderr.txt') }
        $json | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Directory 'exec-summary.json')
    }
    Write-Host "saved $Label exec artifacts to $Directory"
    return $json
}

$bv = Find-Bvmenv
Write-Host "bvmenv: $bv"
Write-Host "host safety: no driver is loaded on this host; all kernel code runs in VM '$Vm'"

# ------------------------------- build -------------------------------
if (-not $SkipBuild) {
    Push-Location $repo
    try {
        & xmake f -y -m release | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'xmake configure failed' }
        & xmake -y
        if ($LASTEXITCODE -ne 0) { throw 'xmake build failed' }
    }
    finally { Pop-Location }
}
# reuse run-e2e's build/sign/bundle preparation
$prepare = Join-Path $PSScriptRoot 'run-e2e.ps1'
& pwsh -NoProfile -File $prepare -Vm $Vm -Bvmenv $bv -Out $Out -SkipCrashRun -PrepareOnly
if ($LASTEXITCODE -ne 0) { throw 'prepare (build/sign/bundle) failed' }
$bundle = Join-Path $Out 'bundle'
$crashBundle = Join-Path $Out 'crash-bundle'

# -------------------------- ensure VM up ------------------------------
$list = Invoke-Bvmenv @('list', '--json')
$listJson = $list.Output | ConvertFrom-Json
if (-not ($listJson.vms | Where-Object { $_.name -eq $Vm })) {
    Write-Host "creating VM $Vm"
    $created = Invoke-Bvmenv @('create', $Vm, '--cpus', '4', '--memory', '6144', '--no-start')
    Write-Host $created.Output
    if ($created.ExitCode -ne 0) { throw 'bvmenv create failed' }
}
$started = Invoke-Bvmenv @('start', $Vm, '--no-wait')

# The guest may still be booting (or sitting at the logon UI): exec falls back
# to a SYSTEM scheduled task, so "guest ops respond" is the only prerequisite.
Write-Host 'waiting for guest operations (exec fallback)...'
$guestReady = $false
for ($attempt = 0; $attempt -lt 60; ++$attempt) {
    $probe = Invoke-Bvmenv @('exec', $Vm, '--timeout', '30', '--', 'cmd', '/c', 'echo kc-ready')
    if ($probe.ExitCode -eq 0 -and $probe.Output -match 'kc-ready') {
        $guestReady = $true
        break
    }
    Start-Sleep -Seconds 10
}
if (-not $guestReady) {
    throw "guest operations did not become available in VM '$Vm'"
}Write-Host $started.Output

# ------------------------- main matrix (exec) --------------------------
$guestMain = 'C:\blook\kc-main'
Write-Host '--- pushing main bundle ---'
$push = Invoke-Bvmenv @('push', $Vm, $bundle, $guestMain)
Write-Host $push.Output
if ($push.ExitCode -ne 0) { throw 'push main bundle failed' }

Write-Host '--- exec main matrix (SYSTEM fallback, no interactive desktop needed) ---'
$mainDir = Join-Path $Out 'main-exec'
$mainExec = Invoke-Bvmenv @('exec', $Vm, '--timeout', '1800',
    '--env', "BLOOK_VM_GUEST=$Vm", '--env', 'BLOOK_ALLOW_KERNEL_LOAD=1',
    '--', 'cmd', '/c', "$guestMain\run-guest-exec.cmd")
$mainJson = Save-ExecArtifacts -Directory $mainDir -ExecResult $mainExec -Label 'main'

# pull artifacts the guest wrote into the pushed bundle
$pull = Invoke-Bvmenv @('pull', $Vm, $guestMain, (Join-Path $mainDir 'guest-artifacts'))
if ($pull.ExitCode -ne 0) { Write-Host "warning: pull failed: $($pull.Output)" }

# host-side observation
$stateMain = Invoke-Bvmenv @('state', $Vm, '--json')
$stateMain.Output | Set-Content (Join-Path $mainDir 'state-after.json')
$screenMain = Join-Path $mainDir 'screen-after.png'
$shot = Invoke-Bvmenv @('screenshot', $Vm, $screenMain)
Write-Host $shot.Output

$stdoutPath = Join-Path $mainDir 'stdout.txt'
$guestOk = $false
if (Test-Path $stdoutPath) {
    $stdoutText = Get-Content $stdoutPath -Raw
    $failLines = ([regex]::Matches($stdoutText, '\[FAIL\]')).Count
    $guestOk = ($failLines -eq 0) -and ($stdoutText -match '"ok":\s*true')
    Write-Host "guest matrix: failing checks=$failLines"
} else {
    Write-Host 'warning: no guest stdout captured'
}
$mainOutcome = if ($guestOk -and $mainJson -and $mainJson.ok) { 'pass' } else { 'fail' }
Write-Host "main outcome: $mainOutcome"

# ------------------------ crash matrix (exec) -------------------------
$crashOutcome = 'skipped'
if (-not $SkipCrashRun) {
    $guestCrash = 'C:\blook\kc-crash'
    $pushCrash = Invoke-Bvmenv @('push', $Vm, $crashBundle, $guestCrash)
    if ($pushCrash.ExitCode -ne 0) { Write-Host "warning: crash push failed" }
    $crashDir = Join-Path $Out 'crash-exec'
    New-Item -ItemType Directory -Force -Path $crashDir | Out-Null
    Write-Host '--- exec deliberate-BSOD harness ---'
    $crashExec = Invoke-Bvmenv @('exec', $Vm, '--timeout', '300',
        '--env', "BLOOK_VM_GUEST=$Vm", '--env', 'BLOOK_ALLOW_KERNEL_LOAD=1',
        '--', 'cmd', '/c', "$guestCrash\run-crash-exec.cmd")
    $crashJson = Save-ExecArtifacts -Directory $crashDir -ExecResult $crashExec -Label 'crash'
    # wait for the bugcheck to be visible to the host-side classifier
    $classified = $false
    for ($attempt = 0; $attempt -lt 30; ++$attempt) {
        Start-Sleep -Seconds 3
        $state = Invoke-Bvmenv @('state', $Vm, '--json')
        $state.Output | Set-Content (Join-Path $crashDir "state-after-$attempt.json")
        try { $stateJson = $state.Output | ConvertFrom-Json } catch { continue }
        if ($stateJson.screen.classification -eq 'bsod') {
            $classified = $true
            if ($stateJson.screen.screenshot) {
                Copy-Item $stateJson.screen.screenshot (Join-Path $crashDir 'screen-bsod.png') -ErrorAction SilentlyContinue
            }
            break
        }
        if ($stateJson.power -eq 'off') { break }
    }
    $crashOutcome = if ($classified) { 'bsod' } else { 'fail' }
    Write-Host "crash outcome: $crashOutcome"
    # leave the VM clean for the next user
    $reset = Invoke-Bvmenv @('reset', $Vm)
    Write-Host $reset.Output
}

# ---------------------------- summary --------------------------------
$summary = [ordered]@{
    schema         = 'blook-kchannel.e2e.v1'
    transport      = 'bvmenv-exec'
    vm             = $Vm
    repo_commit    = (& git -C $repo rev-parse HEAD)
    timestamp      = (Get-Date -Format o)
    version        = $version
    main_outcome   = $mainOutcome
    crash_outcome  = $crashOutcome
    evidence_dir   = $Out
}
$summary | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Out 'result.json')
Write-Host ($summary | ConvertTo-Json -Depth 4)

# render performance tables from the pulled guest stdout
$metrics = Join-Path $mainDir 'stdout.txt'
if (Test-Path $metrics) {
    $metricObjects = New-Object System.Collections.Generic.List[object]
    $text = Get-Content $metrics -Raw
    foreach ($match in [regex]::Matches($text, '\{[^\r\n]*\}')) {
        if ($match.Value -notmatch '"median_ns"|"worker_cpu_percent"|"stop_ns"|"mapped_expectation"') { continue }
        try { $metricObjects.Add(($match.Value | ConvertFrom-Json)) } catch { }
    }
    $metricObjects.ToArray() | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Out 'metrics.json')
    $render = Join-Path $PSScriptRoot 'render-performance.ps1'
    if (Test-Path $render) {
        & pwsh -NoProfile -File $render -Evidence $Out -Doc (Join-Path $repo 'docs/performance.md')
    }
}

if ($mainOutcome -ne 'pass') { exit 1 }
if (-not $SkipCrashRun -and $crashOutcome -ne 'bsod') { exit 1 }
exit 0
