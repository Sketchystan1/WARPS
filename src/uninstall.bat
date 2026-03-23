@echo off
setlocal EnableExtensions

for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do set "ESC=%%b"
set "RED=%ESC%[91m"
set "GREEN=%ESC%[92m"
set "YELLOW=%ESC%[93m"
set "RESET=%ESC%[0m"

set "SCRIPT_DIR=%~dp0"
set "PROXY_DLL_NAME=userenv.dll"
set "INSTALL_DIR=C:\Program Files\Cloudflare\Cloudflare WARP"

if /i "%1"=="elevated" goto :uninstall_now

net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo %YELLOW%[*] Requesting admin rights...%RESET%
    powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList 'elevated' -WorkingDirectory '%SCRIPT_DIR%' -Verb RunAs"
    exit /b 0
)

:uninstall_now
echo %YELLOW%[*] Removing WARPS from Cloudflare WARP...%RESET%

echo %YELLOW%[*] Stopping CloudflareWARP service...%RESET%
net stop CloudflareWARP /y >nul 2>&1

if exist "%INSTALL_DIR%\%PROXY_DLL_NAME%" (
    echo %YELLOW%[*] Deleting proxy DLL...%RESET%
    del /f /q "%INSTALL_DIR%\%PROXY_DLL_NAME%"
    if errorlevel 1 (
        echo %RED%[!] Failed to delete %PROXY_DLL_NAME%. Access denied?%RESET%
    ) else (
        echo %GREEN%[+] %PROXY_DLL_NAME% removed successfully.%RESET%
    )
) else (
    echo %YELLOW%[*] %PROXY_DLL_NAME% not found in installation directory.%RESET%
)

if exist "%INSTALL_DIR%\sni.txt" (
    echo %YELLOW%[*] Deleting sni.txt...%RESET%
    del /f /q "%INSTALL_DIR%\sni.txt"
    if errorlevel 1 (
        echo %RED%[!] Failed to delete sni.txt. Access denied?%RESET%
    ) else (
        echo %GREEN%[+] sni.txt removed successfully.%RESET%
    )
)

echo %YELLOW%[*] Starting CloudflareWARP service...%RESET%
net start CloudflareWARP >nul 2>&1

echo %GREEN%[+] Uninstallation complete!%RESET%
timeout /t 5
exit /b 0
