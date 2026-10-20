<#
Guest-side e2e matrix for blook-kchannel (bvmenv.e2e.v1 bundle entry).

Runs inside the lab VM, from the pushed bundle directory:
  Phase A - SCM load of kchannel_test.sys (test-signed, dev path)
  Phase B - manual map by kcmapload.sys (stealth path, no device)
  Phase C - unload residue + trace scan

Every check appends a line to results.jsonl and the process prints a JSON
summary. A deliberate BSOD is NOT part of this script (see crash-run.ps1) so a
failure here always means a real regression.
#>
param(
    [string]$Region = '0x40000',
    [int]$LatencyCalls = 2000
)

$ErrorActionPreference = 'Continue'
$bundle = $PSScriptRoot
$ctl = Join-Path $bundle 'kchannel-ctl.exe'
$driverDir = Join-Path $env:SystemRoot 'System32\drivers'
$resultsFile = Join-Path $bundle 'results.jsonl'
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

# ---------------------------- preparation ----------------------------
$cert = Join-Path $bundle 'blook-kchannel-test.cer'
if (Test-Path $cert) {
    certutil.exe -addstore -f Root $cert | Out-Null
    certutil.exe -addstore -f TrustedPublisher $cert | Out-Null
}
Copy-Item (Join-Path $bundle 'kchannel_test.sys') $driverDir -Force
Copy-Item (Join-Path $bundle 'kcmapload.sys') $driverDir -Force
Remove-Item 'C:\blook-kchannel-e2e.log' -ErrorAction SilentlyContinue
Record 'prepare' $true "bundle=$bundle"

# ------------------------- phase A: SCM path -------------------------
sc.exe create kchannel_test type= kernel `
    binPath= (Join-Path $driverDir 'kchannel_test.sys') start= demand | Out-Null
$startOutput = sc.exe start kchannel_test 2>&1
Start-Sleep -Milliseconds 800
$stateOutput = sc.exe query kchannel_test 2>&1
Record 'scm_load' ($stateOutput -match 'RUNNING') ($stateOutput -join '; ')

$wrongKey = Invoke-Ctl @('wrong-key', '--device', '\\.\kchannel_test')
Record 'wrong_key_rejected' ($wrongKey.ExitCode -eq 0) $wrongKey.Output

$functional = Invoke-Ctl @('attach-test', '--device', '\\.\kchannel_test', '--region', $Region)
Record 'scm_functional_matrix' ($functional.ExitCode -eq 0) $functional.Output

$second = Invoke-Ctl @('second-attach', '--device', '\\.\kchannel_test', '--region', $Region)
Record 'second_attach_rejected' ($second.ExitCode -eq 0) $second.Output

$events = Invoke-Ctl @('event-test', '--device', '\\.\kchannel_test', '--region', $Region)
Record 'scm_events' ($events.ExitCode -eq 0) $events.Output

$latency = Invoke-Ctl @('latency', '--device', '\\.\kchannel_test', '--region', $Region, '--count', "$LatencyCalls")
Record 'scm_latency' ($latency.ExitCode -eq 0) $latency.Output
if ($latency.Output -match '"ok":true') { $latency.Output | Add-Content (Join-Path $bundle 'latency-scm.json') }

$idle = Invoke-Ctl @('idle-cpu', '--device', '\\.\kchannel_test', '--region', $Region, '--seconds', '10')
Record 'scm_idle_cpu' ($idle.ExitCode -eq 0) $idle.Output
if ($idle.Output -match '"ok":true') { $idle.Output | Add-Content (Join-Path $bundle 'idle-scm.json') }

$kill = Invoke-Ctl @('loader-kill', '--device', '\\.\kchannel_test', '--region', $Region)
Record 'scm_loader_kill_recovery' ($kill.ExitCode -eq 0) $kill.Output

$traceScm = Invoke-Ctl @('trace-scan', '--device', '\\.\kchannel_test')
Record 'scm_trace_scan' ($traceScm.ExitCode -eq 0) $traceScm.Output

# ---------------------- phase A2: unload residue ---------------------
sc.exe stop kchannel_test | Out-Null
Start-Sleep -Milliseconds 500
sc.exe delete kchannel_test | Out-Null
Start-Sleep -Milliseconds 500
$traceAfterUnload = Invoke-Ctl @('trace-scan', '--device', '\\.\kchannel_test')
$noDevice = $traceAfterUnload.Output -match '"device_present":false'
$noServiceKey = $traceAfterUnload.Output -match '"service_key_present":false'
Record 'unload_no_device_or_service' ($noDevice -and $noServiceKey) $traceAfterUnload.Output

# ------------------------ phase B: mapped path -----------------------
sc.exe create kcmapload type= kernel `
    binPath= (Join-Path $driverDir 'kcmapload.sys') start= demand | Out-Null
sc.exe start kcmapload | Out-Null
Start-Sleep -Milliseconds 800
$mapperState = sc.exe query kcmapload 2>&1
Record 'mapper_load' ($mapperState -match 'RUNNING') ($mapperState -join '; ')

$mapped = Invoke-Ctl @('map-test', '--mapper', '\\.\kcmapload', '--image', (Join-Path $bundle 'kchannel_test.sys'), '--region', $Region)
Record 'mapped_functional_matrix' ($mapped.ExitCode -eq 0) $mapped.Output

$mappedEvents = Invoke-Ctl @('event-test', '--mapper', '\\.\kcmapload', '--image', (Join-Path $bundle 'kchannel_test.sys'), '--region', $Region)
Record 'mapped_events' ($mappedEvents.ExitCode -eq 0) $mappedEvents.Output

$mappedLatency = Invoke-Ctl @('latency', '--mapper', '\\.\kcmapload', '--image', (Join-Path $bundle 'kchannel_test.sys'), '--region', $Region, '--count', "$LatencyCalls")
Record 'mapped_latency' ($mappedLatency.ExitCode -eq 0) $mappedLatency.Output
if ($mappedLatency.Output -match '"ok":true') { $mappedLatency.Output | Add-Content (Join-Path $bundle 'latency-mapped.json') }

$mappedIdle = Invoke-Ctl @('idle-cpu', '--mapper', '\\.\kcmapload', '--image', (Join-Path $bundle 'kchannel_test.sys'), '--region', $Region, '--seconds', '10')
Record 'mapped_idle_cpu' ($mappedIdle.ExitCode -eq 0) $mappedIdle.Output
if ($mappedIdle.Output -match '"ok":true') { $mappedIdle.Output | Add-Content (Join-Path $bundle 'idle-mapped.json') }

# Stealth invariants: the mapped driver must have no device object, no service
# key and no entry in the loaded module list.
$traceMapped = Invoke-Ctl @('trace-scan', '--image', (Join-Path $bundle 'kchannel_test.sys'))
Record 'mapped_trace_scan' ($traceMapped.ExitCode -eq 0) $traceMapped.Output
$traceMapped.Output | Add-Content (Join-Path $bundle 'trace-mapped.json')

# ---------------------- phase C: loader death ------------------------
$mappedKill = Invoke-Ctl @('loader-kill', '--image', (Join-Path $bundle 'kchannel_test.sys'), '--mapper', '\\.\kcmapload', '--region', $Region)
Record 'mapped_loader_kill' ($mappedKill.ExitCode -eq 0) $mappedKill.Output
if (Test-Path 'C:\blook-kchannel-e2e.log') {
    Copy-Item 'C:\blook-kchannel-e2e.log' (Join-Path $bundle 'driver-log.txt') -Force
    $log = Get-Content 'C:\blook-kchannel-e2e.log' -Raw
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
    ok         = ($script:failures -eq 0)
    failures   = $script:failures
    checks_file = $resultsFile
    latency_scm    = (Get-Content (Join-Path $bundle 'latency-scm.json') -Raw -ErrorAction SilentlyContinue)
    latency_mapped = (Get-Content (Join-Path $bundle 'latency-mapped.json') -Raw -ErrorAction SilentlyContinue)
    idle_scm       = (Get-Content (Join-Path $bundle 'idle-scm.json') -Raw -ErrorAction SilentlyContinue)
    idle_mapped    = (Get-Content (Join-Path $bundle 'idle-mapped.json') -Raw -ErrorAction SilentlyContinue)
    trace_mapped   = (Get-Content (Join-Path $bundle 'trace-mapped.json') -Raw -ErrorAction SilentlyContinue)
}
($summary | ConvertTo-Json -Depth 4) | Set-Content (Join-Path $bundle 'summary.json')
Write-Host ($summary | ConvertTo-Json -Depth 4)
exit $(if ($script:failures -eq 0) { 0 } else { 1 })
