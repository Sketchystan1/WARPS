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
set "INSTALL_DIR=C:\Program Files\Cloudflare\Cloudflare WARP"

if not exist "%INSTALL_DIR%\%PROXY_DLL_NAME%" (
    echo %RED%[!] %PROXY_DLL_NAME% is not installed in the Cloudflare WARP directory.%RESET%
    echo %YELLOW%[*] Please run install.bat first before using this script.%RESET%
    timeout /t 10
    exit /b 1
)

echo.
echo %RED%Note: You don't need to change these settings. The default configuration is%RESET%
echo %RED%designed to work well for most users. If you prefer to keep it as is,%RESET%
echo %RED%simply close this window.%RESET%
echo.
set /p "TARGET_DOMAIN=Enter the domain for SNI (e.g., google.com): "
if "%TARGET_DOMAIN%"=="" (
    echo %RED%[!] No domain entered. Aborting.%RESET%
    timeout /t 5
    exit /b 1
)

echo %YELLOW%[*] Stopping CloudflareWARP service...%RESET%
net stop CloudflareWARP /y >nul 2>&1

echo %YELLOW%[*] Creating sni.txt with domain: %TARGET_DOMAIN%...%RESET%
echo %TARGET_DOMAIN%> "%INSTALL_DIR%\sni.txt"

echo %YELLOW%[*] Starting CloudflareWARP service...%RESET%
net start CloudflareWARP >nul 2>&1

echo %GREEN%[+] SNI modification complete!%RESET%
timeout /t 5
exit /b 0
