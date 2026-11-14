# escape=`

# antiwire-rs Windows test image
#
# Runs the daemon and the elevated Windows tests inside a disposable Windows container, so a
# test that rewrites firewall rules or adapter DNS touches the container rather than the host.
# The default container user, ContainerAdministrator, is elevated, so no `sudo` window is
# involved and every line of output reaches `docker run`.
#
# Needs Docker switched to Windows containers. Docker Desktop only offers that mode on
# Windows 10/11 Pro, Enterprise, or Education, or on Windows Server.
#
# Build from the antiwire-rs root (not the repo root):
#   docker build -f docker/windows-test.Dockerfile -t antiwire-rs-windows-test .
#
# Unprivileged suites for all three workspaces (default):
#   docker run --rm --isolation=hyperv antiwire-rs-windows-test
#
# Start the daemon, wait for its gRPC listener, and check it stays up:
#   docker run --rm --isolation=hyperv antiwire-rs-windows-test daemon
#
# Elevated live tests (firewall, kernel ETW, DNS redirection), or one workspace's with
# live-daemon, live-netmet or live-firew:
#   docker run --rm --isolation=hyperv antiwire-rs-windows-test live
#
# Everything, or a PowerShell prompt:
#   docker run --rm --isolation=hyperv antiwire-rs-windows-test all
#   docker run --rm -it --isolation=hyperv antiwire-rs-windows-test shell
#
# Hyper-V isolation gives the container its own kernel. Process isolation shares the host
# kernel, so the kernel ETW sessions the tests start would collide with a daemon running on
# the host, and it also requires the host build to match the base image.

FROM mcr.microsoft.com/windows/servercore:ltsc2022

USER ContainerAdministrator
SHELL ["cmd", "/S", "/C"]

# MSVC linker and Windows SDK. `ring` and the bundled SQLite in rusqlite compile C through
# `cc`, which finds these through vswhere. Exit code 3010 means "reboot required" and is fine.
RUN curl.exe -fsSL -o C:\vs_buildtools.exe https://aka.ms/vs/17/release/vs_buildtools.exe `
    && (start /w C:\vs_buildtools.exe --quiet --wait --norestart --nocache `
        --installPath "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools" `
        --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        --add Microsoft.VisualStudio.Component.Windows11SDK.22621 `
        || IF "%ERRORLEVEL%"=="3010" EXIT 0) `
    && del /q C:\vs_buildtools.exe

# The Rust version the workflows in .github/workflows pin; keep them the same.
ENV RUSTUP_HOME=C:\rustup `
    CARGO_HOME=C:\cargo `
    RUST_BACKTRACE=1
RUN curl.exe -fsSL -o C:\rustup-init.exe https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe `
    && C:\rustup-init.exe -y --no-modify-path --profile minimal --default-toolchain 1.100.0 `
        --default-host x86_64-pc-windows-msvc `
    && del /q C:\rustup-init.exe `
    && setx /M PATH "%PATH%;C:\cargo\bin"

# rusqlite is vendored ("bundled") and protoc is supplied by protoc-bin-vendored, so no
# system SQLite, OpenSSL, or protobuf installs are required.

WORKDIR C:\src
COPY . C:\src

# Precompile everything the entrypoint runs, so `docker run` only executes tests.
# `cargo test --no-run` builds the #[ignore]d live tests too.
RUN cargo build -p antiwire-daemon `
    && cargo test --workspace --all-features --no-run `
    && cargo test --manifest-path packages\netmet-rs\Cargo.toml --workspace --all-features --no-run `
    && cargo test --manifest-path packages\firew-rs\Cargo.toml --workspace --all-features --no-run

# Registry sources are not needed to re-run already-built tests.
RUN if exist C:\cargo\registry\src rmdir /s /q C:\cargo\registry\src

COPY docker/windows-test-entrypoint.ps1 C:\entrypoint.ps1

ENTRYPOINT ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "C:\\entrypoint.ps1"]
CMD ["offline"]
