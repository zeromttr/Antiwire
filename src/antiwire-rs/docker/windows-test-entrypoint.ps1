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
        $daemon.WaitForExit()
    }
    # A killed daemon leaves adapter DNS pointed at its own resolver, which is gone. Restore it
    # from the same data directory, or nothing after this step can resolve a name.
    & $exe --heal-host-state --data-dir $dataDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "error: heal-host-state failed with exit code $LASTEXITCODE"
        exit $LASTEXITCODE
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

# The elevated tests from the guides that run in a container, one function per suite. The two
# collector tests are diagnostics: read the numbers they print rather than trusting pass/fail.
# Left out: the WinDivert tests, because containers cannot load its kernel driver (CI runs them
# on its Windows legs), and the capture test, which needs Npcap.
$LiveFlags = @("--ignored", "--test-threads=1", "--nocapture")

function Invoke-LiveDaemon {
    Assert-Elevated
    Show-FirewallServices
    Invoke-Checked "antiwire-enforce live firewall" (@(
        "test", "-p", "antiwire-enforce", "--test", "live_firewall", "--") + $LiveFlags)
    Invoke-Checked "antiwire-enforce shutdown" (@(
        "test", "-p", "antiwire-enforce", "--lib", "--", "firew::shutdown_tests") + $LiveFlags)
    Invoke-Checked "antiwire-enforce stale test rules" (@(
        "test", "-p", "antiwire-enforce", "--test", "stale_test_rules", "--") + $LiveFlags)
    Invoke-Checked "antiwire-flow live byte pipeline" (@(
        "test", "-p", "antiwire-flow", "--test", "live_byte_pipeline", "--") + $LiveFlags)
    # Rewrites adapter DNS, which in a container is the container's own adapter.
    Invoke-Checked "antiwire-dns-os windows redirect" (@(
        "test", "-p", "antiwire-dns-os", "--test", "windows_dns_redirect", "--") + $LiveFlags)
    Invoke-Checked "antiwire-dns-redirect live redirect" (@(
        "test", "-p", "antiwire-dns-redirect", "--test", "live_redirect", "--") + $LiveFlags)
}

function Invoke-LiveNetmet {
    Assert-Elevated
    Invoke-Checked "netmetrics collector probe" (@(
        "test", "--manifest-path", $Netmet, "-p", "netmetrics", "--test", "collector_probe", "--") +
        $LiveFlags)
    Invoke-Checked "netmetrics native windows" (@(
        "test", "--manifest-path", $Netmet, "-p", "netmetrics", "--test", "native_windows", "--") +
        $LiveFlags)
}

function Invoke-LiveFirew {
    Assert-Elevated
    Show-FirewallServices
    Invoke-Checked "firew-windows live" (@(
        "test", "--manifest-path", $Firew, "-p", "firew-windows", "--test", "live_windows", "--") +
        $LiveFlags + @("--skip", "live_inetfw_address_set_ceiling"))
    Invoke-Checked "firew integration live" (@(
        "test", "--manifest-path", $Firew, "-p", "firew-rs", "--test", "integration",
        "--no-default-features", "--features", "windows", "--") + $LiveFlags)
}

switch ($Mode) {
    "offline" { Invoke-Offline }
    "daemon" { Invoke-Daemon }
    "live-daemon" { Invoke-LiveDaemon }
    "live-netmet" { Invoke-LiveNetmet }
    "live-firew" { Invoke-LiveFirew }
    "live" {
        Invoke-LiveDaemon
        Invoke-LiveNetmet
        Invoke-LiveFirew
    }
    "all" {
        Invoke-Offline
        Invoke-Daemon
        Invoke-LiveDaemon
        Invoke-LiveNetmet
        Invoke-LiveFirew
    }
    "shell" { powershell.exe -NoLogo }
    default {
        Write-Host "usage: entrypoint.ps1 [offline|daemon|live|live-daemon|live-netmet|live-firew|all|shell]"
        exit 2
    }
}
