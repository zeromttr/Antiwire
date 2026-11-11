# Entrypoint for docker/windows-test.Dockerfile. Runs under Windows PowerShell 5.1, which is
# what servercore ships, so this avoids PowerShell 7 syntax such as `&&` and `?:`.
param(
    [string]$Mode = "offline"
)

$ErrorActionPreference = "Stop"
# Overridable so the script can be checked against a host checkout outside the container.
$Root = if ($env:ANTIWIRE_SRC) { $env:ANTIWIRE_SRC } else { "C:\src" }
$Netmet = "packages\netmet-rs\Cargo.toml"
$Firew = "packages\firew-rs\Cargo.toml"

Set-Location $Root

# Native commands do not throw on failure, so check every exit code.
function Invoke-Checked {
    param([string]$Title, [string[]]$CargoArgs)
    Write-Host "== $Title =="
    & cargo @CargoArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "error: $Title failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
    }
}

# Every live mode assumes an elevated token. ContainerAdministrator has one; a container started
# with `--user ContainerUser` does not, and its failures would read as broken tests.
function Assert-Elevated {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "error: this mode needs an elevated token; run as ContainerAdministrator"
        exit 2
    }
}

# Firewall rule tests need the firewall and filtering engine services. Report their state up
# front so a container image without them is not mistaken for a broken test.
function Show-FirewallServices {
    foreach ($name in @("mpssvc", "BFE")) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Write-Host "warning: service $name is not present in this container"
        } else {
            Write-Host "service ${name}: $($service.Status)"
        }
    }
}

# Unprivileged tests across all three workspaces. `cargo test` skips every #[ignore]d test,
# so this tier must stay green whatever the container's privileges.
function Invoke-Offline {
    Invoke-Checked "antiwire-rs" @("test", "--workspace", "--all-features")
    Invoke-Checked "netmet-rs" @("test", "--manifest-path", $Netmet, "--workspace", "--all-features")
    Invoke-Checked "firew-rs" @("test", "--manifest-path", $Firew, "--workspace", "--all-features")
}

# Starts the real daemon in the foreground, waits for its gRPC listener, then checks it is still
# alive a few seconds later, which catches a crash just after bind. Logs are printed either way.
function Invoke-Daemon {
    Assert-Elevated
    $listen = if ($env:ANTIWIRE_LISTEN) { $env:ANTIWIRE_LISTEN } else { "127.0.0.1:50051" }
    $port = [int]($listen.Split(":")[-1])
    $dataDir = Join-Path $env:TEMP "antiwire-data"
    $stdout = Join-Path $env:TEMP "antiwire-daemon.out.log"
    $stderr = Join-Path $env:TEMP "antiwire-daemon.err.log"
    $exe = Join-Path $Root "target\debug\antiwire-daemon.exe"

    Write-Host "== antiwire-daemon =="
    $daemon = Start-Process -FilePath $exe -PassThru -NoNewWindow `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -ArgumentList @("--no-service", "--foreground", "--data-dir", $dataDir, "--listen", $listen)

    $timeout = if ($env:ANTIWIRE_DAEMON_TIMEOUT) { [int]$env:ANTIWIRE_DAEMON_TIMEOUT } else { 60 }
    $listening = $false
    for ($i = 0; $i -lt $timeout; $i++) {
        if ($daemon.HasExited) { break }
        if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
            $listening = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if ($listening) {
        Start-Sleep -Seconds 5
    }
    $alive = -not $daemon.HasExited

    Get-Content $stdout, $stderr -ErrorAction SilentlyContinue
    if ($alive) {
        Stop-Process -Id $daemon.Id -Force
    }

    if (-not $listening) {
        Write-Host "error: daemon did not listen on $listen within ${timeout}s"
        exit 1
    }
    if (-not $alive) {
        Write-Host "error: daemon exited with code $($daemon.ExitCode) after it began listening"
        exit 1
    }
    Write-Host "daemon listened on $listen and stayed up"
}

# The elevated tests from AGENTS.md that make sense in a container. The two `live_*` collector
# tests are diagnostics: read the numbers they print rather than trusting pass/fail. The
# WinDivert test is left out because containers cannot load its kernel driver.
function Invoke-Live {
    Assert-Elevated
    Show-FirewallServices
    $flags = @("--", "--ignored", "--test-threads=1", "--nocapture")

    Invoke-Checked "antiwire-enforce live firewall" (@(
        "test", "-p", "antiwire-enforce", "--test", "live_firewall") + $flags)
    Invoke-Checked "firew-windows live" (@(
        "test", "--manifest-path", $Firew, "-p", "firew-windows", "--test", "live_windows") +
        $flags + @("--skip", "live_inetfw_address_set_ceiling"))
    Invoke-Checked "antiwire-flow live byte pipeline" (@(
        "test", "-p", "antiwire-flow", "--test", "live_byte_pipeline") + $flags)
    Invoke-Checked "netmetrics collector probe" (@(
        "test", "--manifest-path", $Netmet, "-p", "netmetrics", "--test", "collector_probe") + $flags)
    Invoke-Checked "netmetrics native windows" (@(
        "test", "--manifest-path", $Netmet, "-p", "netmetrics", "--test", "native_windows") + $flags)
    # Rewrites adapter DNS, which here is the container's own adapter rather than the host's.
    Invoke-Checked "antiwire-dns-os windows redirect" (@(
        "test", "-p", "antiwire-dns-os", "--test", "windows_dns_redirect") + $flags)
    Invoke-Checked "antiwire-dns-redirect live redirect" (@(
        "test", "-p", "antiwire-dns-redirect", "--test", "live_redirect") + $flags)
}

switch ($Mode) {
    "offline" { Invoke-Offline }
    "daemon" { Invoke-Daemon }
    "live" { Invoke-Live }
    "all" {
        Invoke-Offline
        Invoke-Daemon
        Invoke-Live
    }
    "shell" { powershell.exe -NoLogo }
    default {
        Write-Host "usage: entrypoint.ps1 [offline|daemon|live|all|shell]"
        exit 2
    }
}
