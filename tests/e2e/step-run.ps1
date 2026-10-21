<#
.SYNOPSIS
    Step-wise VM e2e runner for blook-kchannel.

.DESCRIPTION
    The monolithic guest matrix can hang if one ctl command misbehaves, which
    also blocks `bvmenv pull`. This runner drives each check as its own short
    `bvmenv exec` call with a host-side timeout, pulls its output immediately,
    and records per-step JSON. Kernel code still only runs inside the guest.

    Steps:
      setup      stage signed drivers, create+start kchannel_test service
      scm        wrong-key, functional matrix, second attach, events,
                 tamper cases, latency (64B/4KB/64KB), copy-mode latency,
                 worker CPU, stop latency, soak, loader kill, trace scan
      unload     stop/delete the SCM driver, verify no device/service residue
      mapped     kcmapload + manual map: functional, events, latency, soak,
                 mapped trace scan, loader death
      cleanup    stop/delete both services
      crash      deliberate kernel fault + host screenshot
#>
[CmdletBinding()]
param(
    [string]$Vm = 'vm-kchannel',
    [string]$Out,
    [string]$Bvmenv,
    [switch]$SkipBuild,
    [switch]$SkipCrash
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$version = (Get-Content (Join-Path $repo 'version.txt') -Raw).Trim()
if (-not $Out) { $Out = Join-Path $repo ("docs/evidence/" + (Get-Date -Format 'yyyyMMdd') + '-vm-e2e') }
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path

function Find-Bvmenv {
    if ($Bvmenv) { return (Resolve-Path $Bvmenv).Path }
    foreach ($candidate in @(
        'D:\blook-kernel-project\blook-vmware-environment\dist\bvmenv-latest.exe',
        'D:\blook-kernel-project\blook-vmware-environment\dist\bvmenv.exe')) {
        if (Test-Path $candidate) { return (Resolve-Path $candidate).Path }
    }
    throw 'bvmenv not found'
}

$bv = Find-Bvmenv
Write-Host "bvmenv: $bv"
Write-Host "host safety: no driver is loaded on this host; kernel code runs only in VM '$Vm'"

# build / sign / bundle (reuses run-e2e -PrepareOnly)
if (-not $SkipBuild) {
    & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'run-e2e.ps1') -Vm $Vm -Bvmenv $bv -Out $Out -SkipCrashRun -PrepareOnly
    if ($LASTEXITCODE -ne 0) { throw 'prepare failed' }
}
$bundle = Join-Path $Out 'bundle'
$signed = Join-Path $Out 'signed'
$guestDir = 'C:\blook\kc-step'
$stepsDir = Join-Path $Out 'steps'
New-Item -ItemType Directory -Force -Path $stepsDir | Out-Null

function Invoke-Exec {
    param([string]$Name, [string]$CommandLine, [int]$TimeoutSeconds = 180)
    $arguments = @('exec', $Vm, '--timeout', "$TimeoutSeconds",
        '--env', "BLOOK_VM_GUEST=$Vm", '--env', 'BLOOK_ALLOW_KERNEL_LOAD=1',
        '--', 'cmd', '/c', $CommandLine)
    $output = & $bv @arguments 2>&1 | Out-String
    $exit = $LASTEXITCODE
    $file = Join-Path $stepsDir ("{0:D2}-{1}.txt" -f $script:stepIndex, $Name)
    $output | Set-Content $file
    $timedOut = $output -match 'timed_out\s*:\s*true'
    $rc = $null
    if ($output -match 'exit_code\s*:\s*(-?\d+)') { $rc = [int]$Matches[1] }
    $ok = (-not $timedOut) -and ($rc -eq 0)
    Write-Host ("[{0}] {1} rc={2} timed_out={3}" -f ($(if ($ok) { 'PASS' } else { 'FAIL' })), $Name, $rc, $timedOut)
    $success = $ok
    $script:stepIndex++
    $result = [ordered]@{ name = $Name; ok = $success; exit_code = $rc; timed_out = $timedOut; output_file = (Split-Path $file -Leaf) }
    ($result | ConvertTo-Json -Compress) | Add-Content (Join-Path $Out 'steps.jsonl')
    return $success
}

$script:stepIndex = 0
Remove-Item (Join-Path $Out 'steps.jsonl') -ErrorAction SilentlyContinue

# ------------------------------ VM up ---------------------------------
$list = (& $bv list --json 2>&1 | Out-String) | ConvertFrom-Json
if (-not ($list.vms | Where-Object { $_.name -eq $Vm })) {
    & $bv create $Vm --cpus 4 --memory 6144 --no-start | Out-Null
}
& $bv start $Vm --no-wait | Out-Null
$guestReady = $false
for ($attempt = 0; $attempt -lt 60; ++$attempt) {
    $probe = (& $bv exec $Vm --timeout 30 -- cmd /c 'echo kc-ready' 2>&1 | Out-String)
    if ($probe -match 'kc-ready') { $guestReady = $true; break }
    Start-Sleep -Seconds 10
}
if (-not $guestReady) { throw 'guest operations did not become available' }

# stage bundle + drivers once
& $bv push $Vm $bundle $guestDir | Out-Null
$setup = @"
copy /y $guestDir\kchannel_test.sys C:\Windows\System32\drivers\kchannel_test.sys >nul
copy /y $guestDir\kcmapload.sys C:\Windows\System32\drivers\kcmapload.sys >nul
certutil -addstore -f Root $guestDir\blook-kchannel-test.cer >nul 2>&1
certutil -addstore -f TrustedPublisher $guestDir\blook-kchannel-test.cer >nul 2>&1
sc stop kchannel_test >nul 2>&1
sc delete kchannel_test >nul 2>&1
sc stop kcmapload >nul 2>&1
sc delete kcmapload >nul 2>&1
sc create kchannel_test type= kernel binPath= C:\Windows\System32\drivers\kchannel_test.sys start= demand >nul
sc start kchannel_test >nul
"@
$setupLine = ($setup.TrimEnd() -replace "`r`n", ' & ')
Invoke-Exec -Name 'setup' -CommandLine $setupLine -TimeoutSeconds 180 | Out-Null

$ctl = "$guestDir\kchannel-ctl.exe"
$checks = @()

# --------------------------- SCM matrix -------------------------------
$checks += Invoke-Exec 'wrong-key' "$ctl wrong-key --device \\.\kchannel_test"
$checks += Invoke-Exec 'attach-test' "$ctl attach-test --device \\.\kchannel_test --region 0x40000"
$checks += Invoke-Exec 'second-attach' "$ctl second-attach --device \\.\kchannel_test --region 0x40000"
$checks += Invoke-Exec 'events' "$ctl event-test --device \\.\kchannel_test --region 0x40000"
foreach ($case in @('ring', 'geometry', 'attach', 'record', 'truncated')) {
    $checks += Invoke-Exec "tamper-$case" "$ctl tamper --device \\.\kchannel_test --case $case --region 0x40000"
}
foreach ($payload in @(64, 4096)) {
    $checks += Invoke-Exec "latency-$payload" "$ctl latency --device \\.\kchannel_test --region 0x40000 --count 2000 --payload $payload"
}
$checks += Invoke-Exec 'latency-64k' "$ctl latency --device \\.\kchannel_test --region 0x40000 --count 200 --payload 65470"
foreach ($payload in @(64, 4096)) {
    $checks += Invoke-Exec "latency-copy-$payload" "$ctl latency --device \\.\kchannel_test --region 0x40000 --count 2000 --payload $payload --mode copy"
}
$checks += Invoke-Exec 'worker-cpu' "$ctl worker-cpu --device \\.\kchannel_test --region 0x40000 --seconds 10"
$checks += Invoke-Exec 'worker-cpu-copy' "$ctl worker-cpu --device \\.\kchannel_test --region 0x40000 --seconds 10 --mode copy"
$checks += Invoke-Exec 'stop-latency' "$ctl stop-latency --device \\.\kchannel_test --region 0x40000"
$checks += Invoke-Exec 'soak' "$ctl soak --device \\.\kchannel_test --region 0x40000 --count 100000 --payload 64"
$checks += Invoke-Exec 'loader-kill' "$ctl loader-kill --device \\.\kchannel_test --region 0x40000" -TimeoutSeconds 240
$checks += Invoke-Exec 'trace-scan-scm' "$ctl trace-scan --device \\.\kchannel_test"

# ------------------------- unload residue -----------------------------
$unload = "sc stop kchannel_test >nul 2>&1 & sc delete kchannel_test >nul 2>&1 & timeout /t 1 >nul"
Invoke-Exec -Name 'unload-scm' -CommandLine $unload -TimeoutSeconds 120 | Out-Null
$checks += Invoke-Exec 'trace-scan-unloaded' "$ctl trace-scan --device \\.\kchannel_test"

# ---------------------------- mapped path -----------------------------
$mapSetup = "sc create kcmapload type= kernel binPath= C:\Windows\System32\drivers\kcmapload.sys start= demand >nul & sc start kcmapload >nul"
Invoke-Exec -Name 'mapper-setup' -CommandLine $mapSetup -TimeoutSeconds 120 | Out-Null
$mapper = '\\.\kcmapload'
$image = "$guestDir\kchannel_test.sys"
$checks += Invoke-Exec 'mapped-functional' "$ctl map-test --mapper $mapper --image $image --region 0x40000"
$checks += Invoke-Exec 'mapped-events' "$ctl event-test --mapper $mapper --image $image --region 0x40000"
foreach ($payload in @(64, 4096)) {
    $checks += Invoke-Exec "mapped-latency-$payload" "$ctl latency --mapper $mapper --image $image --region 0x40000 --count 2000 --payload $payload"
}
$checks += Invoke-Exec 'mapped-soak' "$ctl soak --mapper $mapper --image $image --region 0x40000 --count 20000 --payload 64"
$checks += Invoke-Exec 'mapped-trace-scan' "$ctl trace-scan --image $image"
$checks += Invoke-Exec 'mapped-loader-kill' "$ctl loader-kill --image $image --mapper $mapper --region 0x40000" -TimeoutSeconds 240
$checks += Invoke-Exec 'traces' "$ctl trace-scan --image $image"

# ------------------------------ cleanup -------------------------------
$cleanup = "sc stop kcmapload >nul 2>&1 & sc delete kcmapload >nul 2>&1 & sc stop kchannel_test >nul 2>&1 & sc delete kchannel_test >nul 2>&1"
Invoke-Exec -Name 'cleanup' -CommandLine $cleanup -TimeoutSeconds 120 | Out-Null

# pull every step output + guest driver log for the host-side evidence
$pullDir = Join-Path $Out 'guest'
New-Item -ItemType Directory -Force -Path $pullDir | Out-Null
foreach ($file in (Get-ChildItem $stepsDir -File)) {
    $guestFile = "C:\blook\kc-step-logs\$($file.Name)"
    & $bv push $Vm $file.FullName $guestFile 2>&1 | Out-Null
}
& $bv pull $Vm 'C:\blook\kchannel-e2e.log' (Join-Path $pullDir 'driver-log.txt') 2>&1 | Out-Null
foreach ($file in (Get-ChildItem $stepsDir -File)) {
    & $bv pull $Vm ("C:\blook\kc-step-logs\" + $file.Name) (Join-Path $pullDir $file.Name) 2>&1 | Out-Null
}

# ------------------------------- crash --------------------------------
$crashOutcome = 'skipped'
if (-not $SkipCrash) {
    $crashBundle = Join-Path $Out 'crash-bundle'
    if (-not (Test-Path $crashBundle)) {
        New-Item -ItemType Directory -Force -Path $crashBundle | Out-Null
        Copy-Item (Join-Path $signed 'kchannel_test.sys') $crashBundle -Force
        Copy-Item (Join-Path $repo 'build\windows\x64\release\kchannel-ctl.exe') $crashBundle -Force
        Copy-Item (Join-Path $Out 'blook-kchannel-test.cer') $crashBundle -Force
    }
    $guestCrash = 'C:\blook\kc-crash'
    & $bv push $Vm $crashBundle $guestCrash | Out-Null
    $crashCmd = "sc create kchannel_test type= kernel binPath= C:\Windows\System32\drivers\kchannel_test.sys start= demand >nul 2>&1 & sc start kchannel_test >nul 2>&1 & $guestCrash\kchannel-ctl.exe crash --device \\.\kchannel_test --region 0x40000"
    $crashExec = & $bv exec $Vm --timeout 120 --env "BLOOK_VM_GUEST=$Vm" --env 'BLOOK_ALLOW_KERNEL_LOAD=1' -- cmd /c $crashCmd 2>&1 | Out-String
    $crashExec | Set-Content (Join-Path $Out 'crash-exec.txt')
    Start-Sleep -Seconds 20
    $screen = Join-Path $Out 'crash-screen.png'
    & $bv screenshot $Vm $screen 2>&1 | Out-Null
    # host-side bugcheck detector: solid Windows bugcheck blue
    $isBsod = $false
    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        $bitmap = [System.Drawing.Bitmap]::FromFile($screen)
        $hits = 0
        $samples = 0
        for ($x = 0; $x -lt $bitmap.Width; $x += 16) {
            for ($y = 0; $y -lt $bitmap.Height; $y += 16) {
                $pixel = $bitmap.GetPixel($x, $y)
                $samples++
                if ([Math]::Abs($pixel.R - 0) -lt 30 -and [Math]::Abs($pixel.G - 120) -lt 40 -and [Math]::Abs($pixel.B - 215) -lt 40) { $hits++ }
            }
        }
        $bitmap.Dispose()
        $ratio = if ($samples -gt 0) { $hits / $samples } else { 0 }
        $isBsod = $ratio -gt 0.25
        Write-Host ("crash screenshot: bugcheck-blue ratio={0:N2}" -f $ratio)
    }
    catch {
        Write-Host "warning: screenshot analysis failed: $($_.Exception.Message)"
    }
    $crashOutcome = if ($isBsod) { 'bsod' } else { 'no-bsod-detected' }
    Write-Host "crash outcome: $crashOutcome"
    & $bv reset $Vm | Out-Null
}

# ------------------------------ summary -------------------------------
$failed = @($checks | Where-Object { -not $_ }).Count
$summary = [ordered]@{
    schema        = 'blook-kchannel.e2e.v1'
    transport     = 'bvmenv-exec-stepwise'
    vm            = $Vm
    repo_commit   = (& git -C $repo rev-parse HEAD)
    timestamp     = (Get-Date -Format o)
    version       = $version
    main_outcome  = if ($failed -eq 0) { 'pass' } else { 'fail' }
    failed_steps  = $failed
    crash_outcome = $crashOutcome
    evidence_dir  = $Out
}
$summary | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Out 'result.json')
Write-Host ($summary | ConvertTo-Json -Depth 4)

# metrics from the per-step outputs
$metrics = New-Object System.Collections.Generic.List[object]
foreach ($file in Get-ChildItem $stepsDir -File) {
    $text = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
    foreach ($match in [regex]::Matches($text, '\{[^\r\n]*\}')) {
        if ($match.Value -notmatch '"median_ns"|"worker_cpu_percent"|"stop_ns"|"mapped_expectation"') { continue }
        try { $metrics.Add(($match.Value | ConvertFrom-Json)) } catch { }
    }
}
$metrics.ToArray() | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Out 'metrics.json')
$render = Join-Path $PSScriptRoot 'render-performance.ps1'
if (Test-Path $render) { & pwsh -NoProfile -File $render -Evidence $Out -Doc (Join-Path $repo 'docs/performance.md') }

& $bv stop $Vm 2>&1 | Out-Null
if ($failed -ne 0) { exit 1 }
if (-not $SkipCrash -and $crashOutcome -ne 'bsod') { exit 1 }
exit 0
