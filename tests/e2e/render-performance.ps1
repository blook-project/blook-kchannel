<#
.SYNOPSIS
    Renders the measured performance numbers from a bvmenv e2e evidence run
    into docs/performance.md (between the PERF:START/PERF:END markers).

.DESCRIPTION
    Input: <Evidence>/metrics.json (array of JSON objects printed by the guest
    `kchannel-ctl` tools: latency, worker-cpu, stop-latency, soak, trace-scan).
    Called automatically by tests/e2e/run-e2e.ps1 after the main run.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Evidence,

    [string]$Doc = (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'docs/performance.md')
)

$ErrorActionPreference = 'Stop'
$metricsPath = Join-Path $Evidence 'metrics.json'
if (-not (Test-Path $metricsPath)) {
    Write-Host "render-performance: no metrics.json in $Evidence (skipped)"
    exit 0
}
$raw = Get-Content $metricsPath -Raw | ConvertFrom-Json
$metrics = @($raw) | Where-Object { $_ -ne $null }

function Get-Field {
    param($Object, [string]$Name, $Default = '')
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function Has-Field {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    $property = $Object.PSObject.Properties[$Name]
    return ($null -ne $property -and $null -ne $property.Value)
}

function Format-Ns([double]$Nanoseconds) {
    if ($Nanoseconds -le 0) { return '-' }
    if ($Nanoseconds -ge 1000) {
        return ('{0:N2} us' -f ($Nanoseconds / 1000.0))
    }
    return ('{0:N0} ns' -f $Nanoseconds)
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('| Load path | Transport | Payload | median | p95 | p99 | cold median |')
$lines.Add('|---|---|---|---|---|---|---|')
$latencies = $metrics | Where-Object { Has-Field $_ 'median_ns' }
foreach ($entry in ($latencies | Sort-Object { Get-Field $_ 'mode' }, { Get-Field $_ 'transport' }, { Get-Field $_ 'payload' })) {
    $lines.Add(('| {0} | {1} | {2} B | {3} | {4} | {5} | {6} |' -f `
                (Get-Field $entry 'mode' '?'), (Get-Field $entry 'transport' 'mapped'),
                (Get-Field $entry 'payload' '?'),
                (Format-Ns (Get-Field $entry 'median_ns' 0)),
                (Format-Ns (Get-Field $entry 'p95_ns' 0)),
                (Format-Ns (Get-Field $entry 'p99_ns' 0)),
                (Format-Ns (Get-Field $entry 'cold_median_ns' 0))))
}

$stop = $metrics | Where-Object { Has-Field $_ 'stop_ns' } | Select-Object -First 1
$workerCpus = $metrics | Where-Object { Has-Field $_ 'worker_cpu_percent' }
$soaks = $metrics | Where-Object { Has-Field $_ 'failures' }
$traces = $metrics | Where-Object { Has-Field $_ 'mapped_expectation' }

$lines.Add('')
$lines.Add('| Measurement | Value |')
$lines.Add('|---|---|')
if ($stop) {
    $lines.Add(('| kc_kernel_stop latency (worker join) | {0} |' -f (Format-Ns (Get-Field $stop 'stop_ns' 0))))
}
foreach ($cpu in $workerCpus) {
    $lines.Add(('| Idle worker-thread CPU ({0} transport, {1} s) | {2:N4} % |' -f `
                (Get-Field $cpu 'transport' 'mapped'), (Get-Field $cpu 'seconds' '?'),
                [double](Get-Field $cpu 'worker_cpu_percent' 0)))
}
foreach ($soakEntry in $soaks) {
    $lines.Add(('| Soak {0} calls x {1} B ({2} transport) | median {3}, p99 {4}, failures {5} |' -f `
                (Get-Field $soakEntry 'calls' '?'), (Get-Field $soakEntry 'payload' '?'),
                (Get-Field $soakEntry 'transport' 'mapped'),
                (Format-Ns (Get-Field $soakEntry 'median_ns' 0)),
                (Format-Ns (Get-Field $soakEntry 'p99_ns' 0)),
                (Get-Field $soakEntry 'failures' '?')))
}
if ($traces) {
    $trace = $traces | Select-Object -Last 1
    $lines.Add(('| Mapped trace scan | device_present={0}, service_key={1}, named_object_match={2}, driver_module={3} |' -f `
                (Get-Field $trace 'device_present' '?'),
                (Get-Field $trace 'service_key_present' '?'),
                (Get-Field $trace 'named_object_match' '?'),
                (Get-Field $trace 'driver_module_present' '?')))
}

$rendered = ($lines -join "`n")

if (-not (Test-Path $Doc)) {
    Write-Host "render-performance: $Doc not found, printing instead"
    Write-Host $rendered
    exit 0
}

$document = Get-Content $Doc -Raw
$startMarker = '<!-- PERF:START -->'
$endMarker = '<!-- PERF:END -->'
$start = $document.IndexOf($startMarker)
$end = $document.IndexOf($endMarker)
if ($start -lt 0 -or $end -lt $start) {
    Write-Host "render-performance: markers missing in $Doc; printing instead"
    Write-Host $rendered
    exit 0
}
$updated = $document.Substring(0, $start + $startMarker.Length) + "`n" + $rendered + "`n" +
           $document.Substring($end)
[System.IO.File]::WriteAllText($Doc, $updated)
Write-Host "render-performance: updated $Doc from $Evidence"
