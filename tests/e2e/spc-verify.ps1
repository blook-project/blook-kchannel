param(
    [string]$Bvmenv = 'D:\blook-kernel-project\blook-vmware-environment\dist\bvmenv-6e83eb6.exe',
    [string]$Vm = 'vm-kchannel',
    [string]$Out = 'docs\evidence\20261021-vm-spc'
)
$ErrorActionPreference = 'Stop'
$env:BVMENV_MAX_RUNNING_VMS = '4'
$repo = 'D:\blook-kernel-project\blook-kchannel'
Set-Location $repo
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$log = Join-Path $Out 'run.log'
Remove-Item $log -ErrorAction SilentlyContinue
function L([string]$m) {
    $line = '[' + (Get-Date -Format HH:mm:ss) + '] ' + $m
    Add-Content -Path $log -Value $line
    Write-Host $line
}
function Run-Exec([string]$command, [int]$timeout) {
    $out = & $Bvmenv exec $Vm --timeout $timeout -- cmd /c $command 2>&1 | Out-String
    return [pscustomobject]@{ Output = $out; Exit = $LASTEXITCODE }
}
function Wait-Guest([int]$attempts = 40) {
    for ($i = 0; $i -lt $attempts; ++$i) {
        $probe = Run-Exec 'echo KC-READY' 20
        if ($probe.Output -match 'KC-READY') { return $true }
        Start-Sleep -Seconds 8
    }
    return $false
}
function Save([string]$name, [string]$text) {
    Set-Content -Path (Join-Path $Out $name) -Value $text
}

L 'SPC SHA-1 verification with explicit boot state'
$bcdeditExe = 'bcdedit'
& $Bvmenv stop $Vm 2>&1 | Out-Null
& $Bvmenv delete $Vm --force 2>&1 | Out-Null
& $Bvmenv create $Vm --cpus 4 --memory 6144 --no-start 2>&1 | Out-Null
& $Bvmenv start $Vm --no-wait 2>&1 | Out-Null
if (-not (Wait-Guest)) { L 'guest not ready'; exit 1 }

# boot / signing state
$bcd = Run-Exec ($bcdeditExe + ' /enum {current}') 60
Save 'bcdedit-current.txt' (($bcd.Output -replace "`r`n", "`n"))
L ('bcdedit: ' + (($bcd.Output -replace "`r`n", ' | ').Trim()))
$globals = Run-Exec ($bcdeditExe + ' /enum {globalsettings}') 60
Save 'bcdedit-globals.txt' (($globals.Output -replace "`r`n", "`n"))
$ts = Run-Exec 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v UpgradedSystem' 30
$tsign = Run-Exec ($bcdeditExe + ' /enum {current} | findstr /i testsigning') 30
L ('testsigning line: ' + (($tsign.Output -replace "`r`n", ' | ').Trim()))

# sign (record exact command)
$drv = Join-Path $env:TEMP 'kc-verify-driver.sys'
Copy-Item (Join-Path $repo 'build\windows\x64\release\kchannel_test.sys') $drv -Force
$signCmd = 'pwsh scripts/sign-driver.ps1 -ImportTsaRoot -Sha1 -Driver ' + $drv
$signOut = & pwsh -NoProfile -File (Join-Path $repo 'scripts\sign-driver.ps1') -Driver $drv -Sha1 -ImportTsaRoot 2>&1 | Out-String
Save 'sign-output.txt' ($signCmd + "`n" + $signOut)
L ('sign: ' + (($signOut -replace "`r`n", ' | ').Trim()))

$xinda = Join-Path $env:TEMP 'xinda.cer'
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -match 'XINDA' } | Select-Object -First 1
Export-Certificate -Cert $cert -FilePath $xinda -Type CERT | Out-Null
$files = @(
    @($drv, 'C:\blook\kchannel_test.sys'),
    @($xinda, 'C:\blook\xinda.cer'),
    @((Join-Path $repo 'signer\tsa\tsa-root.cer'), 'C:\blook\tsa-root.cer'),
    @((Join-Path $repo 'signer\certs\verisign-cscs-2010.cer'), 'C:\blook\verisign-cscs-2010.cer'),
    @((Join-Path $repo 'signer\certs\verisign-g5-mcvr.cer'), 'C:\blook\verisign-g5-mcvr.cer'),
    @((Join-Path $repo 'build\windows\x64\release\kchannel-ctl.exe'), 'C:\blook\kchannel-ctl.exe'),
    @('Y:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe', 'C:\blook\signtool.exe')
)
foreach ($f in $files) { $null = & $Bvmenv push $Vm $f[0] $f[1] 2>&1 }

$trust = @(
    'certutil -addstore -f root C:\blook\tsa-root.cer',
    'certutil -addstore -f CA C:\blook\verisign-cscs-2010.cer',
    'certutil -addstore -f CA C:\blook\verisign-g5-mcvr.cer',
    'certutil -addstore -f TrustedPublisher C:\blook\xinda.cer'
) -join ' & '
$tr = Run-Exec $trust 120
Save 'cert-trust.txt' (($tr.Output -replace "`r`n", "`n"))
$stores = Run-Exec 'certutil -store root & certutil -store CA & certutil -store TrustedPublisher' 120
Save 'certutil-stores.txt' (($stores.Output -replace "`r`n", "`n"))

$kp = Run-Exec 'C:\blook\signtool.exe verify /kp /v C:\blook\kchannel_test.sys' 120
Save 'signtool-kp.txt' (($kp.Output -replace "`r`n", "`n"))
L ('/kp exit=' + $kp.Exit)

function Try-Load([string]$label) {
    $cmd = @(
        'copy /y C:\blook\kchannel_test.sys C:\Windows\System32\drivers\kchannel_test.sys',
        'sc create kchannel_test type= kernel binPath= C:\Windows\System32\drivers\kchannel_test.sys start= demand',
        'sc start kchannel_test',
        'sc query kchannel_test'
    ) -join ' & '
    $r = Run-Exec $cmd 120
    Save ($label + '-load.txt') (($r.Output -replace "`r`n", "`n"))
    L ($label + ': ' + (($r.Output -replace "`r`n", ' | ').Trim()))
    $null = Run-Exec 'sc stop kchannel_test & sc delete kchannel_test' 60
    return $r
}

$first = Try-Load 'load-before-testsigning-off'
$tsOn = (($tsign.Output + $bcd.Output + $globals.Output) -match 'testsigning\s+Yes')
if ($true) {
    L 'forcing testsigning off + nointegritychecks off, then rebooting'
    $null = Run-Exec ($bcdeditExe + ' /set testsigning off & ' + $bcdeditExe + ' /set nointegritychecks off') 60
    $null = Run-Exec 'shutdown /r /t 0' 20
    Start-Sleep -Seconds 15
    if (-not (Wait-Guest 60)) { L 'guest did not return after reboot'; & $Bvmenv stop $Vm 2>&1 | Out-Null; exit 1 }
    $bcd2 = Run-Exec ($bcdeditExe + ' /enum {current}') 60
    Save 'bcdedit-current-testsigning-off.txt' (($bcd2.Output -replace "`r`n", "`n"))
    $tsign2 = Run-Exec ($bcdeditExe + ' /enum {current} | findstr /i testsigning') 30
    L ('testsigning after reboot: ' + (($tsign2.Output -replace "`r`n", ' | ').Trim()))
    $kp2 = Run-Exec 'C:\blook\signtool.exe verify /kp /v C:\blook\kchannel_test.sys' 120
    Save 'signtool-kp-testsigning-off.txt' (($kp2.Output -replace "`r`n", "`n"))
    $second = Try-Load 'load-after-testsigning-off'
} else {
    L 'testsigning is OFF already'
    Save 'bcdedit-current-testsigning-off.txt' (($bcd.Output -replace "`r`n", "`n"))
}

& $Bvmenv stop $Vm 2>&1 | Out-Null
L 'done'
