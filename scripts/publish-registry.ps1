<#
.SYNOPSIS
    Publishes (or updates) the blook-kchannel package in
    blook-project/blook-xmake-repo after a GitHub release exists.

.DESCRIPTION
    The registry stores one package manifest and a versions.txt file with
    "<version> <sha256>" lines. This script:
      1. clones (or reuses) blook-xmake-repo,
      2. copies the package manifest from xmake-package/xmake.lua,
      3. downloads the release zip and verifies/records its SHA256 in
         versions.txt,
      4. commits and pushes (skipped with -DryRun).

.EXAMPLE
    pwsh scripts/publish-registry.ps1 -Version 1.0.0 -DryRun
    pwsh scripts/publish-registry.ps1 -Version 1.0.0
#>
[CmdletBinding()]
param(
    [string]$Package = 'blook-kchannel',

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$ManifestFile = (Join-Path $PSScriptRoot '..\xmake-package\xmake.lua'),

    [string]$RegistryDir,

    [string]$Sha256,

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Resolve-RegistryDir {
    param([string]$Directory)
    if ($Directory) {
        if (-not (Test-Path (Join-Path $Directory '.git'))) {
            throw "'$Directory' is not a git clone of blook-xmake-repo"
        }
        return (Resolve-Path $Directory).Path
    }
    $clone = Join-Path $env:TEMP ('blook-xmake-repo-' + [guid]::NewGuid().ToString('N'))
    Write-Host "cloning blook-xmake-repo -> $clone"
    gh repo clone blook-project/blook-xmake-repo $clone -- --depth 1
    if ($LASTEXITCODE -ne 0) { throw 'gh repo clone failed' }
    return (Resolve-Path $clone).Path
}

function Get-ReleaseZipHash {
    param([string]$Tag, [string]$PackageName, [string]$VersionValue)
    if ($Sha256) { return $Sha256.ToLower() }
    $temp = Join-Path $env:TEMP ('kchannel-release-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $temp | Out-Null
    $pattern = "$PackageName-$VersionValue-windows-x64.zip"
    Write-Host "downloading release asset $pattern from tag $Tag"
    gh release download $Tag --pattern $pattern --dir $temp
    if ($LASTEXITCODE -ne 0) { throw "release asset $pattern not found on tag $Tag" }
    $zip = Get-ChildItem $temp -Filter *.zip | Select-Object -First 1
    $hash = (Get-FileHash $zip.FullName -Algorithm SHA256).Hash.ToLower()
    $sidecar = "$($zip.FullName).sha256"
    if (Test-Path $sidecar) {
        $recorded = (Get-Content $sidecar -Raw).Split(' ')[0].Trim().ToLower()
        if ($recorded -ne $hash) { throw "sidecar hash mismatch: $recorded != $hash" }
        Write-Host 'sidecar hash verified'
    }
    return $hash
}

$registry = Resolve-RegistryDir -Directory $RegistryDir
if (-not (Test-Path $ManifestFile)) { throw "manifest '$ManifestFile' not found" }

$letter = $Package.Substring(0, 1).ToLowerInvariant()
$packageDir = Join-Path $registry "packages/$letter/$Package"
New-Item -ItemType Directory -Force -Path $packageDir | Out-Null

# 1. manifest
Copy-Item $ManifestFile (Join-Path $packageDir 'xmake.lua') -Force
Write-Host "manifest -> $packageDir/xmake.lua"

# 2. sha256 from the release asset
$hash = Get-ReleaseZipHash -Tag "v$Version" -PackageName $Package -VersionValue $Version
Write-Host "sha256($Package $Version) = $hash"

# 3. versions.txt
$versionsFile = Join-Path $packageDir 'versions.txt'
$lines = @()
if (Test-Path $versionsFile) {
    $lines = Get-Content $versionsFile | Where-Object { $_ -and ($_ -notmatch "^\s*$Version\s") }
}
$lines += "$Version $hash"
[System.IO.File]::WriteAllLines($versionsFile, [string[]]$lines)
Write-Host "versions.txt updated:"
Get-Content $versionsFile | ForEach-Object { Write-Host "  $_" }

# 4. commit / push
Push-Location $registry
try {
    git add (Join-Path $packageDir 'xmake.lua') (Join-Path $packageDir 'versions.txt')
    git status --short
    if ($DryRun) {
        Write-Host '-DryRun: not committing'
        return
    }
    git -c user.name='MicroBlock' -c user.email='66859419+std-microblock@users.noreply.github.com' commit -m "registry: $Package $Version"
    if ($LASTEXITCODE -ne 0) { throw 'git commit failed' }
    git push origin main
    if ($LASTEXITCODE -ne 0) { throw 'git push failed' }
    Write-Host "registry updated: $Package $Version"
}
finally {
    Pop-Location
}
