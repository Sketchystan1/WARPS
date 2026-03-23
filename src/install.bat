@echo off
setlocal EnableExtensions

for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do set "ESC=%%b"
set "RED=%ESC%[91m"
set "GREEN=%ESC%[92m"
set "YELLOW=%ESC%[93m"
set "RESET=%ESC%[0m"

set "SCRIPT_DIR=%~dp0"
set "PROXY_DLL_NAME=userenv.dll"
set "PROXY_BUILD_DLL=%SCRIPT_DIR%%PROXY_DLL_NAME%"

if not exist "%PROXY_BUILD_DLL%" (
    echo %RED%[!] %PROXY_DLL_NAME% not found in the current directory.%RESET%
    echo %YELLOW%[*] Please run this script from the build output folder.%RESET%
    timeout /t 5
    exit /b 1
)

if /i "%1"=="elevated" goto :install_now

net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo %YELLOW%[*] Requesting admin rights...%RESET%
    powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList 'elevated' -WorkingDirectory '%SCRIPT_DIR%' -Verb RunAs"
    exit /b 0
)

:install_now
echo %YELLOW%[*] Installing to Cloudflare WARP directory...%RESET%
set "INSTALL_DIR=C:\Program Files\Cloudflare\Cloudflare WARP"

echo %YELLOW%[*] Stopping CloudflareWARP service...%RESET%
net stop CloudflareWARP /y >nul 2>&1

echo %YELLOW%[*] Copying files...%RESET%
copy /y "%PROXY_BUILD_DLL%" "%INSTALL_DIR%\%PROXY_DLL_NAME%" >nul
if errorlevel 1 (
    echo %RED%[!] Failed to install proxy DLL. Access denied?%RESET%
    net start CloudflareWARP >nul 2>&1
    timeout /t 5
    exit /b 1
)

echo %YELLOW%[*] Starting CloudflareWARP service...%RESET%
net start CloudflareWARP >nul 2>&1

echo %YELLOW%[*] Configuring tunnel protocol to MASQUE...%RESET%
"%INSTALL_DIR%\warp-cli.exe" tunnel protocol set MASQUE >nul 2>&1

echo %GREEN%[+] Installation complete!%RESET%
timeout /t 5
exit /b 0
