[CmdletBinding()]
param(
    [string]$LogPath = (Join-Path $env:TEMP "netmetrics-elevated-tests.log")
)

$ErrorActionPreference = "Continue"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$exitCode = 1

Push-Location $repositoryRoot
try {
    & cargo.exe test `
        -p netmetrics `
        --test native_windows `
        --all-features `
        -- `
        --ignored `
        --test-threads=1 `
        --nocapture 2>&1 | Tee-Object -FilePath $LogPath
    $exitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}

Write-Host "Elevated test log: $LogPath"
exit $exitCode
