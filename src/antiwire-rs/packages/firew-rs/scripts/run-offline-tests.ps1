#Requires -Version 5.1
$ErrorActionPreference = "Stop"
$PackageRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $PackageRoot

function Invoke-CargoChecked {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

Write-Host "Running firew-rs offline tests from $PackageRoot"

Invoke-CargoChecked @("test", "--manifest-path", "crates/firew-core/Cargo.toml")
Invoke-CargoChecked @("test", "--manifest-path", "crates/firew-sys/Cargo.toml")
Invoke-CargoChecked @("test", "--manifest-path", "crates/firew/Cargo.toml")
Invoke-CargoChecked @("test", "--manifest-path", "crates/firew-windows/Cargo.toml", "--lib")
Invoke-CargoChecked @("test", "--manifest-path", "crates/firew-windows/Cargo.toml", "--test", "rule_naming")
Invoke-CargoChecked @("test", "--manifest-path", "crates/firew-linux/Cargo.toml", "--lib")
Invoke-CargoChecked @("test", "--manifest-path", "crates/firew-linux/Cargo.toml", "--test", "detect_offline")
Invoke-CargoChecked @("test", "--manifest-path", "crates/firew-macos/Cargo.toml", "--lib")

Write-Host "firew-rs offline tests completed."
