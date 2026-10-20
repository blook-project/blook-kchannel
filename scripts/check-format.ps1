<#
.SYNOPSIS
    clang-format gate used by CI and locally before committing.

.DESCRIPTION
    Checks every C/C++ source in include/, src/ and tests/ against the repo
    .clang-format. Requires clang-format 20.1.0 (the version CI installs via
    pip) to keep results deterministic.
#>
[CmdletBinding()]
param(
    [switch]$Fix
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$style = "file:$root/.clang-format"

$clangFormat = Get-Command clang-format -ErrorAction SilentlyContinue
if (-not $clangFormat) { throw 'clang-format not found on PATH' }
Write-Host "using $(& clang-format --version)"

$files = Get-ChildItem (Join-Path $root 'include'), (Join-Path $root 'src'), (Join-Path $root 'tests') `
    -Recurse -Include *.cpp, *.h
$unformatted = @()
foreach ($file in $files) {
    if ($Fix) {
        & clang-format -i --style=$style $file.FullName
    }
    $formatted = & clang-format --style=$style $file.FullName
    $original = Get-Content $file.FullName -Raw
    $normalized = ($formatted -join "`n") + "`n"
    if ($original -ne $normalized) {
        $unformatted += $file.FullName
    }
}

if ($Fix) {
    Write-Host "formatted $($files.Count) files"
    exit 0
}
if ($unformatted.Count -gt 0) {
    Write-Host 'files not formatted (run scripts/check-format.ps1 -Fix):'
    $unformatted | ForEach-Object { Write-Host "  $_" }
    exit 1
}
Write-Host "all $($files.Count) files are formatted"
