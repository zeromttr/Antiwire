@echo off
setlocal
cd /d "%~dp0.."
set LOG=%~dp0..\elevated-test-output.txt
net session >nul 2>&1 && (echo ELEVATED=yes) > "%LOG%" || (echo ELEVATED=no) > "%LOG%"
net session >nul 2>&1
if not "%ERRORLEVEL%"=="0" (
    echo FINAL_EXIT=1 >> "%LOG%"
    echo === finished %DATE% %TIME% === >> "%LOG%"
    exit /b 1
)
echo === firew-rs elevated tests started %DATE% %TIME% === >> "%LOG%"
cargo test --manifest-path crates\firew-windows\Cargo.toml --test live_windows -- --ignored --test-threads=1 --nocapture --skip live_inetfw_address_set_ceiling >> "%LOG%" 2>&1
set WIN_EXIT=%ERRORLEVEL%
echo WINDOWS_EXIT=%WIN_EXIT% >> "%LOG%"
cargo test --manifest-path crates\firew\Cargo.toml --test integration -- --ignored --test-threads=1 --nocapture >> "%LOG%" 2>&1
set INT_EXIT=%ERRORLEVEL%
echo INTEGRATION_EXIT=%INT_EXIT% >> "%LOG%"
set FINAL_EXIT=0
if not "%WIN_EXIT%"=="0" set FINAL_EXIT=%WIN_EXIT%
if "%FINAL_EXIT%"=="0" if not "%INT_EXIT%"=="0" set FINAL_EXIT=%INT_EXIT%
echo FINAL_EXIT=%FINAL_EXIT% >> "%LOG%"
echo === finished %DATE% %TIME% === >> "%LOG%"
exit /b %FINAL_EXIT%
