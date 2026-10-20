# Guest-side BSOD-safety run: loads kchannel_test.sys through the SCM and asks
# the driver to fault on purpose. bvmenv classifies the crash (outcome "bsod")
# and captures the host-side screenshot/stop code. This proves the harness can
# detect a real kernel crash, so a "pass" in guest-run.ps1 means something.
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
