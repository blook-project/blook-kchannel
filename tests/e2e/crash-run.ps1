# Guest-side BSOD-safety run: loads kchannel_test.sys through the SCM and asks
# the driver to fault on purpose. bvmenv classifies the crash (outcome "bsod")
# and captures the host-side screenshot/stop code. This proves the harness can
# detect a real kernel crash, so a "pass" in guest-run.ps1 means something.

# ---------------------------------------------------------------------------
# HOST SAFETY: this script loads kernel drivers with sc create/start and
# manual-maps test drivers. It must only ever run inside a bvmenv VMware guest
# fork - never on the physical host. Refuse to continue otherwise.
# ---------------------------------------------------------------------------
$vmGuestMarker = (Test-Path 'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools') -and (Test-Path 'C:\blook\provision.json')
$envGuestMarker = ($env:BLOOK_VM_GUEST -eq '1') -or ($env:BVMENV_GUEST -eq '1')
if (-not ($vmGuestMarker -or $envGuestMarker)) {
    Write-Host '{"ok":false,"error":"REFUSING to run: kernel e2e must execute inside a bvmenv VMware guest, not on the host"}'
    exit 3
}
$ErrorActionPreference = 'Continue'
$bundle = $PSScriptRoot
$ctl = Join-Path $bundle 'kchannel-ctl.exe'
$driverDir = Join-Path $env:SystemRoot 'System32\drivers'

$cert = Join-Path $bundle 'blook-kchannel-test.cer'
if (Test-Path $cert) {
    certutil.exe -addstore -f Root $cert | Out-Null
    certutil.exe -addstore -f TrustedPublisher $cert | Out-Null
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
