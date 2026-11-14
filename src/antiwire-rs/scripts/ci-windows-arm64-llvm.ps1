# Puts clang on PATH for a Windows ARM64 build on a CI runner, installing LLVM when the image
# has none. ring assembles its ARM64 code with clang, which cl.exe cannot do. Used by the native
# ARM64 test leg (.github/workflows/ci.yml) and by the cross-compiled ARM64 packages
# (release.yml, packages.yml).
$ErrorActionPreference = "Stop"

$Llvm = "C:\Program Files\LLVM\bin"
if (-not (Test-Path "$Llvm\clang.exe")) {
    # Native commands do not throw on failure, so check the exit code.
    choco install llvm -y --no-progress
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
Add-Content $env:GITHUB_PATH $Llvm
