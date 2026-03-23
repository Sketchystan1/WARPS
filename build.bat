@echo off
setlocal EnableExtensions

:main
:: Shift arguments if we were called with a flag (for compatibility)
if "%~1"=="--internal-standalone" shift

for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do set "ESC=%%b"
set "RED=%ESC%[91m"
set "GREEN=%ESC%[92m"
set "YELLOW=%ESC%[93m"
set "RESET=%ESC%[0m"

:: Configuration
set VCVARS="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat"
set "ROOT_DIR=%~dp0"
set "BUILD_DIR=%ROOT_DIR%build"
set "OBJ_DIR=%BUILD_DIR%\obj"
set "PROXY_DLL_NAME=userenv.dll"
set "PROXY_DEF_FILE=src\userenv.def"
set "PROXY_BUILD_DLL=%BUILD_DIR%\%PROXY_DLL_NAME%"
set "COMMON_SOURCES=src\dllmain.cpp src\hooks.c src\udp_hook.c"

:: Load version
if exist "%ROOT_DIR%VERSION" (
    set /p WARPS_VERSION=<"%ROOT_DIR%VERSION"
) else (
    set "WARPS_VERSION=1.0.0"
)

:: Parse version into major.minor.patch
set "VERSION_MAJOR=0"
set "VERSION_MINOR=0"
set "VERSION_PATCH=0"
for /f "tokens=1,2,3 delims=." %%a in ("%WARPS_VERSION%") do (
    if not "%%a"=="" set "VERSION_MAJOR=%%a"
    if not "%%b"=="" set "VERSION_MINOR=%%b"
    if not "%%c"=="" set "VERSION_PATCH=%%c"
)

:: Prepare version header
(
    echo #define VERSION_MAJOR %VERSION_MAJOR%
    echo #define VERSION_MINOR %VERSION_MINOR%
    echo #define VERSION_PATCH %VERSION_PATCH%
    echo #define VERSION_STR "%WARPS_VERSION%"
) > "%ROOT_DIR%src\version.h"

if not exist %VCVARS% (
    echo %RED%[!] Visual Studio 2026 not found at %VCVARS%%RESET%
    timeout /t 10
    exit /b 1
)
set "CL_FLAGS=/O2 /DNDEBUG /DWARPS_ENABLE_STATIC_HOSTNAME_PATCHES=1 /DWARPS_VERSION=\"%WARPS_VERSION%\""
set "LINK_FLAGS=/NOLOGO /DLL /INCREMENTAL:NO /RELEASE"

:: Compile
echo %YELLOW%Building...%RESET%
call %VCVARS% amd64 >nul 2>&1
pushd "%ROOT_DIR%"

if exist "%BUILD_DIR%" rmdir /S /Q "%BUILD_DIR%"
mkdir "%OBJ_DIR%"
if errorlevel 1 goto :error

:: Compile resources
rc.exe /nologo /fo"%OBJ_DIR%\version.res" src\version.rc.in >nul 2>&1
if errorlevel 1 goto :error

:: Use /Fd to ensure the compiler's vc*.pdb is placed in the object directory instead of the root
cl.exe /nologo /c /W3 /DWIN32 /D_WINDOWS /D_CRT_SECURE_NO_WARNINGS /MT /I. %CL_FLAGS% /EHsc /Fd"%OBJ_DIR%\\" /Fo"%OBJ_DIR%\\" %COMMON_SOURCES% >nul 2>&1
if errorlevel 1 goto :error

ml64.exe /nologo /c /Fo"%OBJ_DIR%\userenv_proxy_stubs.obj" src\userenv_proxy_stubs.asm >nul 2>&1
if errorlevel 1 goto :error

link.exe %LINK_FLAGS% /OUT:"%PROXY_BUILD_DLL%" /DEF:"%PROXY_DEF_FILE%" "%OBJ_DIR%\*.obj" "%OBJ_DIR%\version.res" kernel32.lib user32.lib gdi32.lib ws2_32.lib bcrypt.lib >nul 2>&1
if errorlevel 1 goto :error

:: Assets & Cleanup
copy /y "src\install.bat" "%BUILD_DIR%\install.bat" >nul
copy /y "src\uninstall.bat" "%BUILD_DIR%\uninstall.bat" >nul
copy /y "src\edit_sni.bat" "%BUILD_DIR%\edit_sni.bat" >nul

if exist "%OBJ_DIR%" rmdir /S /Q "%OBJ_DIR%"
del /Q "%BUILD_DIR%\vc*.pdb" "%BUILD_DIR%\*.exp" "%BUILD_DIR%\*.lib" "%BUILD_DIR%\*.pdb" 2>nul
if exist "src\version.h" del "src\version.h"

:: Packaging
set "VERSIONED_BUILD_DIR_NAME=WARPS_v%WARPS_VERSION%"
set "VERSIONED_BUILD_ZIP=%ROOT_DIR%%VERSIONED_BUILD_DIR_NAME%.zip"
if exist "%VERSIONED_BUILD_ZIP%" del /Q "%VERSIONED_BUILD_ZIP%"

:package_build
:: Archive the build output without renaming the build directory.
tar.exe -a -cf "%VERSIONED_BUILD_ZIP%" -C "%BUILD_DIR%" .
if errorlevel 1 (
    echo %RED%[!] Failed to create %VERSIONED_BUILD_DIR_NAME%.zip%RESET%
    goto :error
)

echo %GREEN%[+] Build v%WARPS_VERSION% complete!%RESET%
popd
timeout /t 5
endlocal
exit /b 0

:error
echo %RED%[!] Build failed%RESET%
if exist "%BUILD_DIR%" rmdir /S /Q "%BUILD_DIR%"
if exist "src\version.h" del "src\version.h"
popd
exit /b 1

