# Guest-side BSOD-safety run: loads kchannel_test.sys through the SCM and asks
# the driver to fault on purpose. bvmenv classifies the crash (outcome "bsod")
# and captures the host-side screenshot/stop code. This proves the harness can
# detect a real kernel crash, so a "pass" in guest-run.ps1 means something.

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


# Remove any stale driver instance from a previous interrupted run and wait
# until the SCM really forgot it (a half-deleted service leaves an old device
# whose default DACL belongs to the previous SYSTEM logon session -> 1359).
foreach ($stale in @('kchannel_test', 'kcmapload')) {
    for ($attempt = 0; $attempt -lt 40; ++$attempt) {
        sc.exe stop $stale 2>$null | Out-Null
        sc.exe delete $stale 2>$null | Out-Null
        Start-Sleep -Milliseconds 250
        $query = sc.exe query $stale 2>&1
        if ($LASTEXITCODE -ne 0) { break }
    }
}
Start-Sleep -Milliseconds 300
foreach ($pair in @(
    @('tsa-root.cer', 'Root'),
    @('verisign-cscs-2010.cer', 'CA'),
    @('verisign-g5-mcvr.cer', 'CA'),
    @('blook-kchannel-xinda.cer', 'TrustedPublisher')
)) {
    $cer = Join-Path $bundle $pair[0]
    if (Test-Path $cer) { certutil.exe -addstore -f $pair[1] $cer | Out-Null }
}
Copy-Item (Join-Path $bundle 'kchannel_test.sys') $driverDir -Force
sc.exe create kchannel_test type= kernel `
    binPath= (Join-Path $driverDir 'kchannel_test.sys') start= demand | Out-Null
sc.exe start kchannel_test | Out-Null
Start-Sleep -Milliseconds 800
Write-Host '{"phase":"crash","note":"invoking deliberate kernel fault"}'
& $ctl crash --device '\\.\kchannel_test' --region 0x40000
Write-Host '{"phase":"crash","ok":false,"note":"driver survived the fault handler"}'
exit 1
