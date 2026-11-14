#Requires -Version 5.1
<#
.SYNOPSIS
    Measures how many remote addresses Windows Firewall accepts in ONE rule.

.DESCRIPTION
    Phase 0 spike for country blocking. The design collapses a whole country's
    CIDR list into a single native Windows rule via INetFw's comma-separated
    RemoteAddresses field. Windows persists each rule to a single registry
    value under
      HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules
    and the practical ceiling is undocumented, so it has to be measured.

    For each size this script verifies the full round trip:
      1. the rule is created
      2. read-back returns the same NUMBER of addresses
      3. read-back returns the same SET of addresses
      4. read-back ORDER is recorded (firew-core compares remote_addresses as
         an ordered Vec, so reordering would make reconcile churn)
      5. the registry value size is recorded
      6. a subsequent unrelated rule add is timed, because INetFw calls
         refresh_from_native() on every add and that enumerates every rule

    Every rule created is removed in the finally block, including on Ctrl-C.

.PARAMETER Sizes
    Address counts to test. Default binary-searches up to the US list size.

.PARAMETER KeepOnFailure
    Leave the failing rule in place for manual inspection.

.PARAMETER ResultPath
    JSON results file, rewritten after every size so a run that is interrupted
    still leaves the sizes it did finish. Windows `sudo` defaults to opening a
    separate window, so this file is usually the only way to see the outcome.

.EXAMPLE
    # From an elevated PowerShell session:
    .\measure-inetfw-address-ceiling.ps1

.EXAMPLE
    # With Windows sudo (new-window mode), then read the results file:
    sudo pwsh -File .\measure-inetfw-address-ceiling.ps1
#>
[CmdletBinding()]
param(
    [int[]]$Sizes = @(1000, 2000, 5000, 10000, 20000, 29319),
    [switch]$KeepOnFailure,
    [string]$ResultPath = (Join-Path $env:TEMP "firew-inetfw-ceiling.json")
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Administrator privileges required. Re-run PowerShell as Administrator, or: sudo pwsh -File $PSCommandPath"
}

$RuleName = "firew_ceiling_probe"
$ProbeName = "firew_ceiling_probe_timing"
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"

# TEST-NET-3 (203.0.113.0/24) is reserved for documentation, but one /24 cannot
# supply 29k distinct networks. 240.0.0.0/4 is reserved-and-unroutable, so
# carving /32s out of it is inert on a real host.
function New-ProbeNetworks {
    param([int]$Count)
    $nets = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Count; $i++) {
        $b1 = 240 + [math]::Floor($i / 16777216)
        $b2 = [math]::Floor(($i % 16777216) / 65536)
        $b3 = [math]::Floor(($i % 65536) / 256)
        $b4 = $i % 256
        $nets.Add("$b1.$b2.$b3.$b4/32")
    }
    return $nets.ToArray()
}

function Remove-ProbeRules {
    foreach ($name in @($RuleName, $ProbeName)) {
        try { Remove-NetFirewallRule -DisplayName $name -ErrorAction Stop } catch { }
    }
}

function Get-RegistryValueBytes {
    param([string]$Match)
    try {
        $key = Get-Item -Path $RegPath -ErrorAction Stop
        foreach ($valueName in $key.GetValueNames()) {
            $value = $key.GetValue($valueName)
            if ($value -is [string] -and $value -like "*$Match*") {
                return $value.Length * 2   # REG_SZ is UTF-16
            }
        }
    } catch { }
    return 0
}

$results = @()

function Save-Results {
    param($Rows, [string]$Path)
    # Rewritten after every size so an interrupted run still reports progress.
    try {
        @($Rows) | ConvertTo-Json -Depth 4 | Set-Content -Path $Path -Encoding utf8
    } catch {
        Write-Host "  (could not write results file: $($_.Exception.Message))" -ForegroundColor Yellow
    }
}

Write-Host "Results file: $ResultPath" -ForegroundColor Cyan
Save-Results -Rows @() -Path $ResultPath

try {
    Remove-ProbeRules

    foreach ($size in $Sizes) {
        Write-Host ""
        Write-Host ("=" * 64)
        Write-Host "Testing $size addresses" -ForegroundColor Cyan
        Write-Host ("=" * 64)

        $nets = New-ProbeNetworks -Count $size
        $row = [ordered]@{
            Size = $size; Created = $false; ReadBackCount = 0
            SetMatches = $false; OrderPreserved = $false
            RegistryBytes = 0; CreateMs = 0; NextAddMs = 0; Error = ""
        }

        try {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            New-NetFirewallRule -DisplayName $RuleName -Direction Outbound `
                -Action Block -RemoteAddress $nets -ErrorAction Stop | Out-Null
            $sw.Stop()
            $row.CreateMs = $sw.ElapsedMilliseconds
            $row.Created = $true
            Write-Host "  created in $($sw.ElapsedMilliseconds) ms" -ForegroundColor Green

            $readBack = (Get-NetFirewallRule -DisplayName $RuleName |
                Get-NetFirewallAddressFilter).RemoteAddress
            if ($readBack -isnot [array]) { $readBack = @($readBack) }
            $row.ReadBackCount = $readBack.Count

            if ($readBack.Count -ne $size) {
                Write-Host "  READ-BACK COUNT MISMATCH: wrote $size, read $($readBack.Count)" -ForegroundColor Red
            } else {
                Write-Host "  read back $($readBack.Count) addresses" -ForegroundColor Green
            }

            # Windows may normalize "x/32" to a bare address; compare on the
            # address part so formatting differences don't read as data loss.
            $wrote = $nets      | ForEach-Object { $_.Split('/')[0] } | Sort-Object
            $read  = $readBack  | ForEach-Object { $_.Split('/')[0] } | Sort-Object
            $row.SetMatches = ($null -eq (Compare-Object $wrote $read))
            if ($row.SetMatches) {
                Write-Host "  set identity preserved" -ForegroundColor Green
            } else {
                Write-Host "  SET IDENTITY LOST" -ForegroundColor Red
            }

            # Order matters: firew-core's Rule PartialEq compares the Vec ordered.
            $writtenOrder = $nets     | ForEach-Object { $_.Split('/')[0] }
            $readOrder    = $readBack | ForEach-Object { $_.Split('/')[0] }
            $row.OrderPreserved = (@(Compare-Object $writtenOrder $readOrder -SyncWindow 0).Count -eq 0)
            if ($row.OrderPreserved) {
                Write-Host "  order preserved" -ForegroundColor Green
            } else {
                Write-Host "  ORDER CHANGED on read-back (sort+dedup in build() is required)" -ForegroundColor Yellow
            }

            $row.RegistryBytes = Get-RegistryValueBytes -Match $RuleName
            if ($row.RegistryBytes -gt 0) {
                Write-Host ("  registry value: {0:N0} bytes ({1:N2} MB)" -f $row.RegistryBytes, ($row.RegistryBytes / 1MB))
            }

            # With a large rule present, how slow is the next unrelated add?
            # This is what INetFw's per-add refresh_from_native() will cost.
            $sw2 = [Diagnostics.Stopwatch]::StartNew()
            New-NetFirewallRule -DisplayName $ProbeName -Direction Outbound `
                -Action Block -RemoteAddress "203.0.113.99" -ErrorAction Stop | Out-Null
            $sw2.Stop()
            $row.NextAddMs = $sw2.ElapsedMilliseconds
            Write-Host "  subsequent unrelated add: $($sw2.ElapsedMilliseconds) ms"
            Remove-NetFirewallRule -DisplayName $ProbeName -ErrorAction SilentlyContinue
        }
        catch {
            $row.Error = $_.Exception.Message
            Write-Host "  FAILED at $size" -ForegroundColor Red
            Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
            $results += [pscustomobject]$row
            Save-Results -Rows $results -Path $ResultPath
            if (-not $KeepOnFailure) { Remove-ProbeRules }
            break
        }

        $results += [pscustomobject]$row
        Save-Results -Rows $results -Path $ResultPath
        Remove-ProbeRules
    }
}
finally {
    if (-not $KeepOnFailure) { Remove-ProbeRules }
}

Write-Host ""
Write-Host ("=" * 64)
Write-Host "RESULTS" -ForegroundColor Cyan
Write-Host ("=" * 64)
$results | Format-Table -AutoSize
Save-Results -Rows $results -Path $ResultPath
Write-Host "Results written to: $ResultPath"

$ok = $results | Where-Object { $_.Created -and $_.SetMatches -and $_.ReadBackCount -eq $_.Size }
if ($ok) {
    $best = ($ok | Measure-Object -Property Size -Maximum).Maximum
    Write-Host ""
    Write-Host "Highest fully-verified size: $best" -ForegroundColor Green
    Write-Host "Set BackendConfig.max_address_set_entries to Some($best) (or lower for margin)."
    $reordered = $ok | Where-Object { -not $_.OrderPreserved }
    if ($reordered) {
        Write-Host "Read-back reordered addresses -> sort+dedup in RuleBuilder::build() is REQUIRED, not optional." -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "No size passed. Windows rejects large address sets on this host;" -ForegroundColor Red
    Write-Host "fall back to chunking (max_address_set_entries = None)." -ForegroundColor Red
}
