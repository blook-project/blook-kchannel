<#
Guest-side e2e matrix for blook-kchannel (bvmenv.e2e.v1 bundle entry).

Runs inside the lab VM, from the pushed bundle directory:
  Phase A - SCM load of kchannel_test.sys (test-signed dev path):
            functional matrix, crash-safety tamper cases, wrong key, duplicate
            attach, events, latency (64 B / 4 KiB / 64 KiB-class), COPY mode,
            worker-thread CPU, stop latency, 100k-message soak, loader kill,
            trace scan, unload residue.
  Phase B - manual map by kcmapload.sys (stealth path, no device at all):
            functional matrix, events, latency, soak, trace scan, loader death
            cleanup (proved from the guest driver log).

A deliberate BSOD is NOT part of this script (see crash-run.ps1) so a failure
here always means a real regression.
#>
param(
    [string]$Region = '0x40000',
    [int]$LatencyCalls = 2000,
    [int]$SoakCalls = 100000
)


# ---------------------------------------------------------------------------
# HOST SAFETY: this script loads kernel drivers with sc create/start and
# manual-maps test drivers. It must only ever run inside a bvmenv VMware guest
# fork - never on the physical host. Refuse to continue otherwise.
# ---------------------------------------------------------------------------
$vmTools = Test-Path 'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools'
$bmenvProvisioned = Test-Path 'C:\blook\provision.json'
$envGuestMarker = ($env:BLOOK_VM_GUEST) -or ($env:BVMENV_GUEST) -or ($env:BLOOK_ALLOW_KERNEL_LOAD -eq '1')
if (-not ($vmTools -and ($bmenvProvisioned -or $envGuestMarker))) {
    Write-Host '{"ok":false,"error":"REFUSING to run: kernel e2e must execute inside a bvmenv VMware guest, not on the host"}'
    exit 3
}
$ErrorActionPreference = 'Continue'
$bundle = $PSScriptRoot
$ctl = Join-Path $bundle 'kchannel-ctl.exe'
$driverDir = Join-Path $env:SystemRoot 'System32\drivers'
$resultsFile = Join-Path $bundle 'results.jsonl'
$image = Join-Path $bundle 'kchannel_test.sys'
Remove-Item $resultsFile -ErrorAction SilentlyContinue
$script:failures = 0

function Record {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    $entry = [ordered]@{
        name   = $Name
        ok     = $Ok
        detail = $Detail
    }
    ($entry | ConvertTo-Json -Compress) | Add-Content -Path $resultsFile
    if (-not $Ok) { $script:failures++ }
    Write-Host ("[{0}] {1} {2}" -f ($(if ($Ok) { 'PASS' } else { 'FAIL' })), $Name, $Detail)
}

function Invoke-Ctl {
    param([string[]]$Arguments)
    $output = & $ctl @Arguments 2>&1
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output   = ($output -join "`n")
    }
}

function Save-Json {
    param([string]$Name, [string]$Json)
    if ($Json -match '"ok":true') {
        $Json | Add-Content (Join-Path $bundle $Name)
    }
}

# ---------------------------- preparation ----------------------------
$cert = Join-Path $bundle 'blook-kchannel-test.cer'
if (Test-Path $cert) {
    certutil.exe -addstore -f Root $cert | Out-Null
    certutil.exe -addstore -f TrustedPublisher $cert | Out-Null
}
Copy-Item (Join-Path $bundle 'kchannel_test.sys') $driverDir -Force
Copy-Item (Join-Path $bundle 'kcmapload.sys') $driverDir -Force

# Remove any stale driver instance from a previous interrupted run so the
# signed .sys can be copied (Windows locks loaded images).
foreach ($stale in @('kchannel_test', 'kcmapload')) {
    sc.exe stop $stale 2>$null | Out-Null
    sc.exe delete $stale 2>$null | Out-Null
}
Start-Sleep -Milliseconds 300Remove-Item 'C:\blook-kchannel-e2e.log' -ErrorAction SilentlyContinue
Record 'prepare' $true "bundle=$bundle"

# ------------------------- phase A: SCM path -------------------------
sc.exe create kchannel_test type= kernel `
    binPath= (Join-Path $driverDir 'kchannel_test.sys') start= demand | Out-Null
$startOutput = sc.exe start kchannel_test 2>&1
Start-Sleep -Milliseconds 800
$service = Get-Service -Name kchannel_test -ErrorAction SilentlyContinue
Record 'scm_load' ($service -and $service.Status -eq 'Running') (($startOutput -join '; ') + " status=$($service.Status)")

$wrongKey = Invoke-Ctl @('wrong-key', '--device', '\\.\kchannel_test')
Record 'wrong_key_rejected' ($wrongKey.ExitCode -eq 0) $wrongKey.Output

$functional = Invoke-Ctl @('attach-test', '--device', '\\.\kchannel_test', '--region', $Region)
Record 'scm_functional_matrix' ($functional.ExitCode -eq 0) $functional.Output

$second = Invoke-Ctl @('second-attach', '--device', '\\.\kchannel_test', '--region', $Region)
Record 'second_attach_rejected' ($second.ExitCode -eq 0) $second.Output

$events = Invoke-Ctl @('event-test', '--device', '\\.\kchannel_test', '--region', $Region)
Record 'scm_events' ($events.ExitCode -eq 0) $events.Output

# Crash-safety: hostile control page / ring mutations must fail the session,
# never the machine. Each case runs against a fresh kernel instance.
foreach ($case in @('ring', 'geometry', 'attach', 'record', 'truncated')) {
    $tamper = Invoke-Ctl @('tamper', '--device', '\\.\kchannel_test', '--case', $case, '--region', $Region)
    Record "scm_tamper_$case" ($tamper.ExitCode -eq 0) $tamper.Output
    $alive = Get-Service -Name kchannel_test -ErrorAction SilentlyContinue
    Record "scm_alive_after_tamper_$case" ($alive -and $alive.Status -eq 'Running') "status=$($alive.Status)"
}

# --------------------------- performance -----------------------------
$lat64 = Invoke-Ctl @('latency', '--device', '\\.\kchannel_test', '--region', $Region, '--count', "$LatencyCalls", '--payload', '64')
Record 'scm_latency_64b' ($lat64.ExitCode -eq 0) $lat64.Output
Save-Json 'latency-scm-64.json' $lat64.Output

$lat4k = Invoke-Ctl @('latency', '--device', '\\.\kchannel_test', '--region', $Region, '--count', "$LatencyCalls", '--payload', '4096')
Record 'scm_latency_4kb' ($lat4k.ExitCode -eq 0) $lat4k.Output
Save-Json 'latency-scm-4k.json' $lat4k.Output

$lat64k = Invoke-Ctl @('latency', '--device', '\\.\kchannel_test', '--region', $Region, '--count', '200', '--payload', '65470')
Record 'scm_latency_64k' ($lat64k.ExitCode -eq 0) $lat64k.Output
Save-Json 'latency-scm-64k.json' $lat64k.Output

$copy64 = Invoke-Ctl @('latency', '--device', '\\.\kchannel_test', '--region', $Region, '--count', "$LatencyCalls", '--payload', '64', '--mode', 'copy')
Record 'scm_copy_latency_64b' ($copy64.ExitCode -eq 0) $copy64.Output
Save-Json 'latency-copy-64.json' $copy64.Output

$copy4k = Invoke-Ctl @('latency', '--device', '\\.\kchannel_test', '--region', $Region, '--count', "$LatencyCalls", '--payload', '4096', '--mode', 'copy')
Record 'scm_copy_latency_4kb' ($copy4k.ExitCode -eq 0) $copy4k.Output
Save-Json 'latency-copy-4k.json' $copy4k.Output

$workerCpu = Invoke-Ctl @('worker-cpu', '--device', '\\.\kchannel_test', '--region', $Region, '--seconds', '10')
Record 'scm_worker_idle_cpu' ($workerCpu.ExitCode -eq 0) $workerCpu.Output
Save-Json 'worker-cpu-scm.json' $workerCpu.Output

$workerCpuCopy = Invoke-Ctl @('worker-cpu', '--device', '\\.\kchannel_test', '--region', $Region, '--seconds', '10', '--mode', 'copy')
Record 'scm_worker_idle_cpu_copy' ($workerCpuCopy.ExitCode -eq 0) $workerCpuCopy.Output
Save-Json 'worker-cpu-copy.json' $workerCpuCopy.Output

$stopLatency = Invoke-Ctl @('stop-latency', '--device', '\\.\kchannel_test', '--region', $Region)
Record 'scm_stop_latency' ($stopLatency.ExitCode -eq 0) $stopLatency.Output
Save-Json 'stop-latency.json' $stopLatency.Output

$soak = Invoke-Ctl @('soak', '--device', '\\.\kchannel_test', '--region', $Region, '--count', "$SoakCalls", '--payload', '64')
Record 'scm_soak' ($soak.ExitCode -eq 0) $soak.Output
Save-Json 'soak-scm.json' $soak.Output

$kill = Invoke-Ctl @('loader-kill', '--device', '\\.\kchannel_test', '--region', $Region)
Record 'scm_loader_kill_recovery' ($kill.ExitCode -eq 0) $kill.Output

$traceScm = Invoke-Ctl @('trace-scan', '--device', '\\.\kchannel_test')
Record 'scm_trace_scan' ($traceScm.ExitCode -eq 0) $traceScm.Output

# ---------------------- phase A2: unload residue ---------------------
sc.exe stop kchannel_test | Out-Null
Start-Sleep -Milliseconds 700
sc.exe delete kchannel_test | Out-Null
Start-Sleep -Milliseconds 700
$traceAfterUnload = Invoke-Ctl @('trace-scan', '--device', '\\.\kchannel_test')
$noDevice = $traceAfterUnload.Output -match '"device_present":false'
$noServiceKey = $traceAfterUnload.Output -match '"service_key_present":false'
Record 'unload_no_device_or_service' ($noDevice -and $noServiceKey) $traceAfterUnload.Output

# ------------------------ phase B: mapped path -----------------------
sc.exe create kcmapload type= kernel `
    binPath= (Join-Path $driverDir 'kcmapload.sys') start= demand | Out-Null
sc.exe start kcmapload | Out-Null
$mapperState = sc.exe query kcmapload 2>&1
$mapperService = Get-Service -Name kcmapload -ErrorAction SilentlyContinue
Record 'mapper_load' ($mapperService -and $mapperService.Status -eq 'Running') (($mapperState -join '; ') + " status=$($mapperService.Status)")

$mapped = Invoke-Ctl @('map-test', '--mapper', '\\.\kcmapload', '--image', $image, '--region', $Region)
Record 'mapped_functional_matrix' ($mapped.ExitCode -eq 0) $mapped.Output

$mappedEvents = Invoke-Ctl @('event-test', '--mapper', '\\.\kcmapload', '--image', $image, '--region', $Region)
Record 'mapped_events' ($mappedEvents.ExitCode -eq 0) $mappedEvents.Output

$mappedLat64 = Invoke-Ctl @('latency', '--mapper', '\\.\kcmapload', '--image', $image, '--region', $Region, '--count', "$LatencyCalls", '--payload', '64')
Record 'mapped_latency_64b' ($mappedLat64.ExitCode -eq 0) $mappedLat64.Output
Save-Json 'latency-mapped-64.json' $mappedLat64.Output

$mappedLat4k = Invoke-Ctl @('latency', '--mapper', '\\.\kcmapload', '--image', $image, '--region', $Region, '--count', "$LatencyCalls", '--payload', '4096')
Record 'mapped_latency_4kb' ($mappedLat4k.ExitCode -eq 0) $mappedLat4k.Output
Save-Json 'latency-mapped-4k.json' $mappedLat4k.Output

$mappedSoak = Invoke-Ctl @('soak', '--mapper', '\\.\kcmapload', '--image', $image, '--region', $Region, '--count', "$([Math]::Min($SoakCalls, 20000))", '--payload', '64')
Record 'mapped_soak' ($mappedSoak.ExitCode -eq 0) $mappedSoak.Output
Save-Json 'soak-mapped.json' $mappedSoak.Output

# Stealth invariants: the mapped driver must have no device object, no service
# key, no named object and no entry in the loaded module list.
$traceMapped = Invoke-Ctl @('trace-scan', '--image', $image)
Record 'mapped_trace_scan' ($traceMapped.ExitCode -eq 0) $traceMapped.Output
$traceMapped.Output | Add-Content (Join-Path $bundle 'trace-mapped.json')

# ---------------------- phase C: loader death ------------------------
$mappedKill = Invoke-Ctl @('loader-kill', '--image', $image, '--mapper', '\\.\kcmapload', '--region', $Region)
Record 'mapped_loader_kill' ($mappedKill.ExitCode -eq 0) $mappedKill.Output
if (Test-Path 'C:\blook-kchannel-e2e.log') {
    Copy-Item 'C:\blook-kchannel-e2e.log' (Join-Path $bundle 'driver-log.txt') -Force
    $log = Get-Content 'C:\blook-kchannel-e2e.log' -Raw
    Write-Host 'DRIVER-LOG-BEGIN'
    Write-Host $log
    Write-Host 'DRIVER-LOG-END'
    $peerGone = $log -match 'peer_gone'
    $destroyed = $log -match 'kc_kernel_destroy'
    Record 'mapped_peer_gone_cleanup' ($peerGone -and $destroyed) 'driver-log.txt'
} else {
    Record 'mapped_peer_gone_cleanup' $false 'driver log missing'
}

sc.exe stop kcmapload | Out-Null
Start-Sleep -Milliseconds 300
sc.exe delete kcmapload | Out-Null

$summary = [ordered]@{
    ok          = ($script:failures -eq 0)
    failures    = $script:failures
    checks_file = $resultsFile
    latency_scm_64    = (Get-Content (Join-Path $bundle 'latency-scm-64.json') -Raw -ErrorAction SilentlyContinue)
    latency_scm_4k    = (Get-Content (Join-Path $bundle 'latency-scm-4k.json') -Raw -ErrorAction SilentlyContinue)
    latency_scm_64k   = (Get-Content (Join-Path $bundle 'latency-scm-64k.json') -Raw -ErrorAction SilentlyContinue)
    latency_copy_64   = (Get-Content (Join-Path $bundle 'latency-copy-64.json') -Raw -ErrorAction SilentlyContinue)
    latency_copy_4k   = (Get-Content (Join-Path $bundle 'latency-copy-4k.json') -Raw -ErrorAction SilentlyContinue)
    latency_mapped_64 = (Get-Content (Join-Path $bundle 'latency-mapped-64.json') -Raw -ErrorAction SilentlyContinue)
    latency_mapped_4k = (Get-Content (Join-Path $bundle 'latency-mapped-4k.json') -Raw -ErrorAction SilentlyContinue)
    worker_cpu_scm    = (Get-Content (Join-Path $bundle 'worker-cpu-scm.json') -Raw -ErrorAction SilentlyContinue)
    worker_cpu_copy   = (Get-Content (Join-Path $bundle 'worker-cpu-copy.json') -Raw -ErrorAction SilentlyContinue)
    stop_latency      = (Get-Content (Join-Path $bundle 'stop-latency.json') -Raw -ErrorAction SilentlyContinue)
    soak_scm          = (Get-Content (Join-Path $bundle 'soak-scm.json') -Raw -ErrorAction SilentlyContinue)
    soak_mapped       = (Get-Content (Join-Path $bundle 'soak-mapped.json') -Raw -ErrorAction SilentlyContinue)
    trace_mapped      = (Get-Content (Join-Path $bundle 'trace-mapped.json') -Raw -ErrorAction SilentlyContinue)
}
($summary | ConvertTo-Json -Depth 4) | Set-Content (Join-Path $bundle 'summary.json')
Write-Host ($summary | ConvertTo-Json -Depth 4)
exit $(if ($script:failures -eq 0) { 0 } else { 1 })
