#Requires -Version 5.1
<#
.SYNOPSIS
    Runs firew-rs live firewall tests with elevation.

.DESCRIPTION
    Standalone firew-rs test runner. Builds test binaries first without
    elevation, then runs them through a uniquely identified .cmd script under
    Windows `sudo` (or directly if already Administrator), waits for the
    completion marker, verifies `ELEVATED=yes`, and propagates actual exit codes.

.PARAMETER LogPath
    Path for combined test output.

.PARAMETER UseSudo
    Force `sudo` even when already elevated.

.PARAMETER TimeoutSeconds
    Maximum seconds to wait for elevated test completion (default 300).
#>
[CmdletBinding()]
param(
    [string]$LogPath = (Join-Path $env:TEMP "firew-rs-elevated-tests.log"),
    [switch]$UseSudo,
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"
$PackageRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $PackageRoot

if (Test-Path $LogPath) {
    Remove-Item $LogPath -Force
}

$packageLog = Join-Path $PackageRoot "elevated-test-output.txt"
if (Test-Path $packageLog) {
    Remove-Item $packageLog -Force
}

Write-Host "Building elevated test binaries..."
& cargo test --manifest-path crates/firew-windows/Cargo.toml --test live_windows --no-run
if ($LASTEXITCODE -ne 0) {
    throw "Failed to build live_windows test binary (exit code $LASTEXITCODE)"
}
& cargo test --manifest-path crates/firew/Cargo.toml --test integration --no-run
if ($LASTEXITCODE -ne 0) {
    throw "Failed to build integration test binary (exit code $LASTEXITCODE)"
}

$depsDir = Join-Path $PackageRoot "target\debug\deps"
$winExe = (Get-ChildItem (Join-Path $depsDir "live_windows-*.exe") | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$intExe = (Get-ChildItem (Join-Path $depsDir "integration-*.exe") | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName

if (-not $winExe -or -not $intExe) {
    throw "Could not locate built test executables in $depsDir"
}

$runId = [Guid]::NewGuid().ToString("N")
$tempOut = Join-Path $env:TEMP "firew-rs-elevated-$runId.log"
$tempCmd = Join-Path $env:TEMP "firew-rs-elevated-$runId.cmd"

Set-Content -Path $tempCmd -Encoding Ascii -Value @"
@echo off
setlocal
net session >nul 2>&1 && (echo ELEVATED=yes) > "$tempOut" || (echo ELEVATED=no) > "$tempOut"
"$winExe" --ignored --test-threads=1 --nocapture --skip live_inetfw_address_set_ceiling >> "$tempOut" 2>&1
set WIN_EXIT=%ERRORLEVEL%
echo WINDOWS_EXIT=%WIN_EXIT% >> "$tempOut"
"$intExe" --ignored --test-threads=1 --nocapture >> "$tempOut" 2>&1
set INT_EXIT=%ERRORLEVEL%
echo INTEGRATION_EXIT=%INT_EXIT% >> "$tempOut"
set FINAL_EXIT=0
if not "%WIN_EXIT%"=="0" set FINAL_EXIT=%WIN_EXIT%
if "%FINAL_EXIT%"=="0" if not "%INT_EXIT%"=="0" set FINAL_EXIT=%INT_EXIT%
echo FINAL_EXIT=%FINAL_EXIT% >> "$tempOut"
echo === FIREW_ELEVATED_COMPLETE_$runId === >> "$tempOut"
exit /b %FINAL_EXIT%
"@

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

try {
    if ($UseSudo -or -not $isAdmin) {
        $sudo = Get-Command sudo.exe -ErrorAction SilentlyContinue
        if ($null -eq $sudo) {
            throw "Administrator privileges required. Re-run PowerShell as Administrator or install Windows sudo."
        }
        Write-Host "Running elevated tests via sudo..."
        & $sudo.Source $tempCmd
        if ($LASTEXITCODE -ne 0) {
            throw "sudo launcher failed with exit code $LASTEXITCODE"
        }
    } else {
        Write-Host "Running elevated tests (already Administrator)..."
        & $tempCmd
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $marker = "=== FIREW_ELEVATED_COMPLETE_$runId ==="
    $completed = $false
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $tempOut) {
            $raw = Get-Content $tempOut -Raw -ErrorAction SilentlyContinue
            if ($null -ne $raw -and $raw.Contains($marker)) {
                $completed = $true
                break
            }
        }
        Start-Sleep -Milliseconds 250
    }

    if (-not (Test-Path $tempOut)) {
        throw "Elevated test output file was never created; elevation prompt may have been declined."
    }

    Copy-Item $tempOut $LogPath -Force
    Copy-Item $tempOut $packageLog -Force
    $lines = Get-Content $LogPath
    $lines | ForEach-Object { Write-Host $_ }

    if (-not $completed) {
        throw "Elevated tests timed out after $TimeoutSeconds seconds."
    }

    if ($lines.Count -eq 0 -or $lines[0].Trim() -ne "ELEVATED=yes") {
        throw "Elevated test runner did not execute with Administrator privileges (first line: '$($lines | Select-Object -First 1)')."
    }

    $finalLine = $lines | ForEach-Object { $_.Trim() } | Where-Object { $_ -match "^FINAL_EXIT=(-?\d+)$" } | Select-Object -Last 1
    if (-not $finalLine) {
        throw "Elevated test log missing FINAL_EXIT status."
    }
    $finalExit = [int]($Matches[1])
    Write-Host "Elevated test log: $LogPath (exit code $finalExit)"
    exit $finalExit
}
finally {
    if (Test-Path $tempCmd) {
        Remove-Item $tempCmd -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $tempOut) {
        Remove-Item $tempOut -Force -ErrorAction SilentlyContinue
    }
}
