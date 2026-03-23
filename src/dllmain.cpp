#ifdef __cplusplus
extern "C" {
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "hooks.h"
#include "udp_hook.h"
#include "config.h"
#include "userenv_proxy_exports.h"

#ifndef WARPS_ENABLE_LOG_WINDOW
#define WARPS_ENABLE_LOG_WINDOW 0
#endif

#ifndef WARPS_ENABLE_LOGGING
#define WARPS_ENABLE_LOGGING WARPS_ENABLE_LOG_WINDOW
#endif

#ifndef WARPS_FORCE_FALLBACK_LOG_FILE
#define WARPS_FORCE_FALLBACK_LOG_FILE 0
#endif

#ifndef WARPS_ENABLE_LEGACY_TLS_HOOKS
#define WARPS_ENABLE_LEGACY_TLS_HOOKS 0
#endif

#ifndef WARPS_ENABLE_AWSLC_TLS_HOOKS
#define WARPS_ENABLE_AWSLC_TLS_HOOKS WARPS_ENABLE_LEGACY_TLS_HOOKS
#endif

#ifndef WARPS_ENABLE_STATIC_HOSTNAME_PATCHES
#define WARPS_ENABLE_STATIC_HOSTNAME_PATCHES 0
#endif

#ifndef WARPS_ENABLE_STREAM_TLS_REWRITE
#define WARPS_ENABLE_STREAM_TLS_REWRITE 0
#endif

#if WARPS_ENABLE_LOG_WINDOW
#define LOG_WINDOW_CLASS_NAMEA "WARPSDebugWindow"
#define LOG_WINDOW_TITLEA "WARPS Debug Window"
#define WM_WARPS_FLUSH_LOGS (WM_APP + 1)
#define WM_WARPS_SYNC_SNI (WM_APP + 2)
#define IDC_WARPS_SNI_LABEL 1001
#define IDC_WARPS_SNI_EDIT 1002
#define IDC_WARPS_APPLY_BUTTON 1003
#define IDC_WARPS_LOG_EDIT 1004
#define MAX_LOG_EDIT_TEXT_LENGTH 64000

typedef struct LOG_LINE_NODE_TAG
{
    struct LOG_LINE_NODE_TAG* next;
    char text[1];
} LOG_LINE_NODE;
#endif

#define MAX_LOG_MESSAGE_LENGTH 1024
#define MAX_LOG_LINE_LENGTH 1152
#define MAX_FALLBACK_LOG_LINES 600
#define WARPS_DEFAULT_LOG_FILE "log.txt"
#define WARPS_PROXY_MODULE_NAMEA "userenv.dll"
#define WARPS_PROXY_REAL_MODULE_NAMEW L"userenv_original.dll"
#define WARPS_PROXY_SYSTEM_MODULE_NAMEW L"userenv.dll"

typedef enum CONFIG_LOAD_STATUS_TAG
{
    CONFIG_LOAD_STATUS_NOT_ATTEMPTED = 0,
    CONFIG_LOAD_STATUS_FILE_MISSING,
    CONFIG_LOAD_STATUS_OVERRIDE_LOADED,
    CONFIG_LOAD_STATUS_INVALID_OVERRIDE,
    CONFIG_LOAD_STATUS_READ_ERROR,
    CONFIG_LOAD_STATUS_PATH_ERROR
} CONFIG_LOAD_STATUS;

HMODULE g_hModule = NULL;
BOOL g_bUdpHooksInitialized = FALSE;
BOOL g_bTlsHooksInitialized = FALSE;
FARPROC g_UserenvForwarders[USERENV_PROXY_EXPORT_COUNT] = { 0 };

static HMODULE g_hRealProxyModule = NULL;
static BOOL g_ProxyActive = FALSE;
static BOOL g_ProxyInitialized = FALSE;
static char g_ConfigOverrideSni[MAX_PATH] = { 0 };
static BOOL g_ConfigHasOverride = FALSE;
static CONFIG_LOAD_STATUS g_ConfigLoadStatus = CONFIG_LOAD_STATUS_NOT_ATTEMPTED;
static SRWLOCK g_ConfigLock = SRWLOCK_INIT;

#if WARPS_ENABLE_LOG_WINDOW
BOOL g_bCanCreateLogWindow = FALSE;
BOOL g_bUseFallbackLogFile = FALSE;
HWND g_hLogWindow = NULL;
HWND g_hLogEdit = NULL;
HWND g_hSniLabel = NULL;
HWND g_hSniEdit = NULL;
HWND g_hApplyButton = NULL;
SRWLOCK g_LogQueueLock = SRWLOCK_INIT;
LOG_LINE_NODE* g_pLogQueueHead = NULL;
LOG_LINE_NODE* g_pLogQueueTail = NULL;
LONG g_LogWindowRequested = 0;
char g_FallbackLogFilePath[MAX_PATH] = { 0 };
static BOOL g_FallbackLogResetForSession = FALSE;
static DWORD g_PreviousFallbackLogLineCount = 0;
#endif

void LogMessage(const char* format, ...);
BOOL Config_Load(void);
BOOL Config_CopySNI(char* buffer, size_t bufferLen);
static void InitializeModule(void);
static void StartInitializationWorker(void);
static void ShutdownModule(void);
static BOOL TryBuildModuleSiblingPathA(const char* fileName, char* path, size_t pathLen);
static void GetProxyModuleName(char* buffer, size_t bufferLength);
static void ResetProxyLoader(void);
static BOOL IsProxyModule(HMODULE module);
static BOOL TryBuildModuleSiblingPathW(
    HMODULE module,
    const wchar_t* fileName,
    wchar_t* path,
    size_t pathCapacity);
static BOOL TryBuildSystemModulePathW(
    const wchar_t* fileName,
    wchar_t* path,
    size_t pathCapacity);
static BOOL ProxyLoader_InitializeForCurrentModule(HMODULE module);
static void ProxyLoader_CleanupForCurrentModule(void);
static BOOL ProxyLoader_IsActive(void);
static void ResetConfigState(CONFIG_LOAD_STATUS status);
static char* TrimWhitespace(char* str);
static BOOL TryReadOverrideSni(
    const char* filePath,
    char* buffer,
    size_t bufferLen,
    CONFIG_LOAD_STATUS* outStatus);
static BOOL TryDeriveDefaultSni(char* buffer, size_t bufferLen);
static BOOL TryStripWarpMasqueLabel(const char* hostName, const char** outRemainder);

#if WARPS_ENABLE_LOG_WINDOW
static BOOL TryBuildProgramDataLogPath(const char* fileName, char* path, size_t pathLen);
static BOOL TryGetFallbackLogFilePath(char* path, size_t pathLen);
static BOOL IsInteractiveDebugSession(void);
static void EnableFallbackLogFile(void);
static void ResetFallbackLogFileIfTooLarge(void);
static void QueueLogLine(const char* line);
static LOG_LINE_NODE* DetachQueuedLogLines(void);
static void AppendLineToFallbackLogFile(const char* text);
static void AppendTextToLogWindow(const char* text);
static void FlushQueuedLogLinesToWindow(void);
static void SyncSniEditWithConfig(void);
static void ApplyWindowSNIChange(void);
static void LayoutLogWindow(HWND hwnd, int width, int height);
static void MaybeStartLogWindow(void);
static DWORD WINAPI LogWindowThread(LPVOID parameter);
static LRESULT CALLBACK LogWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
#endif

static BOOL TryBuildModuleSiblingPathA(const char* fileName, char* path, size_t pathLen)
{
    char modulePath[MAX_PATH];
    char* lastSlash;

    if (!fileName || !path || pathLen == 0)
    {
        return FALSE;
    }

    path[0] = '\0';
    if (!g_hModule ||
        !GetModuleFileNameA(g_hModule, modulePath, sizeof(modulePath)))
    {
        return FALSE;
    }

    lastSlash = strrchr(modulePath, '\\');
    if (!lastSlash)
    {
        return FALSE;
    }

    *(lastSlash + 1) = '\0';
    if (strlen(modulePath) + strlen(fileName) >= pathLen)
    {
        return FALSE;
    }

    strcpy_s(path, pathLen, modulePath);
    strcat_s(path, pathLen, fileName);
    return TRUE;
}

static void ResetProxyLoader(void)
{
    memset(g_UserenvForwarders, 0, sizeof(g_UserenvForwarders));

    if (g_hRealProxyModule)
    {
        FreeLibrary(g_hRealProxyModule);
        g_hRealProxyModule = NULL;
    }

    g_ProxyActive = FALSE;
    g_ProxyInitialized = FALSE;
}

static BOOL IsProxyModule(HMODULE module)
{
    char modulePath[MAX_PATH];
    const char* moduleName;

    if (!module ||
        !GetModuleFileNameA(module, modulePath, sizeof(modulePath)))
    {
        return FALSE;
    }

    moduleName = strrchr(modulePath, '\\');
    moduleName = moduleName ? (moduleName + 1) : modulePath;
    return _stricmp(moduleName, WARPS_PROXY_MODULE_NAMEA) == 0;
}

static BOOL TryBuildModuleSiblingPathW(
    HMODULE module,
    const wchar_t* fileName,
    wchar_t* path,
    size_t pathCapacity)
{
    wchar_t modulePath[MAX_PATH];
    wchar_t* lastSlash;

    if (!module || !fileName || !path || pathCapacity == 0)
    {
        return FALSE;
    }

    path[0] = L'\0';
    if (!GetModuleFileNameW(module, modulePath, MAX_PATH))
    {
        return FALSE;
    }

    lastSlash = wcsrchr(modulePath, L'\\');
    if (!lastSlash)
    {
        return FALSE;
    }

    *(lastSlash + 1) = L'\0';
    if (wcslen(modulePath) + wcslen(fileName) >= pathCapacity)
    {
        return FALSE;
    }

    wcscpy_s(path, pathCapacity, modulePath);
    wcscat_s(path, pathCapacity, fileName);
    return TRUE;
}

static BOOL TryBuildSystemModulePathW(
    const wchar_t* fileName,
    wchar_t* path,
    size_t pathCapacity)
{
    UINT systemPathLength;

    if (!fileName || !path || pathCapacity == 0)
    {
        return FALSE;
    }

    path[0] = L'\0';
    systemPathLength = GetSystemDirectoryW(path, (UINT)pathCapacity);
    if (systemPathLength == 0 || systemPathLength >= pathCapacity)
    {
        return FALSE;
    }

    if (path[systemPathLength - 1] != L'\\')
    {
        if ((size_t)systemPathLength + 1 >= pathCapacity)
        {
            return FALSE;
        }

        path[systemPathLength] = L'\\';
        path[systemPathLength + 1] = L'\0';
    }

    if (wcslen(path) + wcslen(fileName) >= pathCapacity)
    {
        return FALSE;
    }

    wcscat_s(path, pathCapacity, fileName);
    return TRUE;
}

static BOOL ProxyLoader_InitializeForCurrentModule(HMODULE module)
{
    wchar_t realPath[MAX_PATH];
    size_t index;

    if (g_ProxyInitialized)
    {
        return TRUE;
    }

    if (!IsProxyModule(module))
    {
        g_ProxyInitialized = TRUE;
        g_ProxyActive = FALSE;
        return TRUE;
    }

    g_ProxyActive = TRUE;
    realPath[0] = L'\0';

    if (!TryBuildModuleSiblingPathW(
            module,
            WARPS_PROXY_REAL_MODULE_NAMEW,
            realPath,
            sizeof(realPath) / sizeof(realPath[0])) ||
        GetFileAttributesW(realPath) == INVALID_FILE_ATTRIBUTES)
    {
        if (!TryBuildSystemModulePathW(
                WARPS_PROXY_SYSTEM_MODULE_NAMEW,
                realPath,
                sizeof(realPath) / sizeof(realPath[0])))
        {
            ResetProxyLoader();
            return FALSE;
        }
    }

    g_hRealProxyModule = LoadLibraryW(realPath);
    if (!g_hRealProxyModule)
    {
        ResetProxyLoader();
        return FALSE;
    }

    for (index = 0; index < USERENV_PROXY_EXPORT_COUNT; ++index)
    {
        if (g_UserenvProxyExports[index].procName)
        {
            g_UserenvForwarders[index] = GetProcAddress(
                g_hRealProxyModule,
                g_UserenvProxyExports[index].procName);
        }
        else
        {
            g_UserenvForwarders[index] = GetProcAddress(
                g_hRealProxyModule,
                (LPCSTR)(ULONG_PTR)g_UserenvProxyExports[index].ordinal);
        }

        if (!g_UserenvForwarders[index])
        {
            ResetProxyLoader();
            return FALSE;
        }
    }

    g_ProxyActive = TRUE;
    g_ProxyInitialized = TRUE;
    return TRUE;
}

static void ProxyLoader_CleanupForCurrentModule(void)
{
    ResetProxyLoader();
}

static BOOL ProxyLoader_IsActive(void)
{
    return g_ProxyActive;
}

static void ResetConfigState(CONFIG_LOAD_STATUS status)
{
    AcquireSRWLockExclusive(&g_ConfigLock);
    g_ConfigOverrideSni[0] = '\0';
    g_ConfigHasOverride = FALSE;
    g_ConfigLoadStatus = status;
    ReleaseSRWLockExclusive(&g_ConfigLock);
}

static char* TrimWhitespace(char* str)
{
    char* start;
    char* end;

    if (!str)
    {
        return NULL;
    }

    start = str;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')
    {
        start++;
    }

    if (*start == '\0')
    {
        str[0] = '\0';
        return str;
    }

    end = start + strlen(start);
    while (end > start &&
           (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
    {
        end--;
    }

    *end = '\0';
    if (start != str)
    {
        memmove(str, start, (size_t)(end - start) + 1);
    }

    return str;
}

static BOOL TryReadOverrideSni(
    const char* filePath,
    char* buffer,
    size_t bufferLen,
    CONFIG_LOAD_STATUS* outStatus)
{
    char line[MAX_PATH];
    FILE* file;

    if (!filePath || !buffer || bufferLen == 0 || !outStatus)
    {
        return FALSE;
    }

    file = fopen(filePath, "r");
    if (!file)
    {
        *outStatus = CONFIG_LOAD_STATUS_READ_ERROR;
        return FALSE;
    }

    if (!fgets(line, sizeof(line), file))
    {
        fclose(file);
        *outStatus = CONFIG_LOAD_STATUS_INVALID_OVERRIDE;
        return FALSE;
    }

    fclose(file);
    TrimWhitespace(line);
    if (line[0] == '\0')
    {
        *outStatus = CONFIG_LOAD_STATUS_INVALID_OVERRIDE;
        return FALSE;
    }

    strncpy_s(buffer, bufferLen, line, _TRUNCATE);
    *outStatus = CONFIG_LOAD_STATUS_OVERRIDE_LOADED;
    return TRUE;
}

static BOOL TryStripWarpMasqueLabel(const char* hostName, const char** outRemainder)
{
    static const char* const knownPrefixes[] = {
        "consumer-masque-proxy.",
        "consumer-masque.",
        "zt-masque-proxy.",
        "zt-masque."
    };
    size_t index;

    if (!hostName || !outRemainder)
    {
        return FALSE;
    }

    for (index = 0; index < sizeof(knownPrefixes) / sizeof(knownPrefixes[0]); ++index)
    {
        size_t prefixLength = strlen(knownPrefixes[index]);

        if (_strnicmp(hostName, knownPrefixes[index], prefixLength) == 0)
        {
            *outRemainder = hostName + prefixLength;
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL TryDeriveDefaultSni(char* buffer, size_t bufferLen)
{
    static const char kKnownWarpMasqueHost[] = "zt-masque.cloudflareclient.com";
    char derived[MAX_PATH];
    const char* remainder;
    char* clientMarker;

    if (!buffer || bufferLen == 0)
    {
        return FALSE;
    }

    buffer[0] = '\0';

    if (!TryStripWarpMasqueLabel(kKnownWarpMasqueHost, &remainder))
    {
        return FALSE;
    }

    strncpy_s(derived, sizeof(derived), remainder, _TRUNCATE);

    clientMarker = strstr(derived, "client.");
    if (!clientMarker)
    {
        return FALSE;
    }

    memmove(
        clientMarker,
        clientMarker + strlen("client"),
        strlen(clientMarker + strlen("client")) + 1);

    strncpy_s(buffer, bufferLen, derived, _TRUNCATE);
    return buffer[0] != '\0';
}

BOOL Config_Load(void)
{
    char path[MAX_PATH];
    char overrideSni[MAX_PATH];
    DWORD attributes;
    CONFIG_LOAD_STATUS loadStatus;

    if (!TryBuildModuleSiblingPathA("sni.txt", path, sizeof(path)))
    {
        ResetConfigState(CONFIG_LOAD_STATUS_PATH_ERROR);
        return FALSE;
    }

    attributes = GetFileAttributesA(path);
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        ResetConfigState(CONFIG_LOAD_STATUS_FILE_MISSING);
        return FALSE;
    }

    if (!TryReadOverrideSni(path, overrideSni, sizeof(overrideSni), &loadStatus))
    {
        ResetConfigState(loadStatus);
        return FALSE;
    }

    AcquireSRWLockExclusive(&g_ConfigLock);
    strncpy_s(g_ConfigOverrideSni, sizeof(g_ConfigOverrideSni), overrideSni, _TRUNCATE);
    g_ConfigHasOverride = TRUE;
    g_ConfigLoadStatus = CONFIG_LOAD_STATUS_OVERRIDE_LOADED;
    ReleaseSRWLockExclusive(&g_ConfigLock);
    return TRUE;
}

BOOL Config_CopySNI(char* buffer, size_t bufferLen)
{
    BOOL haveOverride = FALSE;

    if (!buffer || bufferLen == 0)
    {
        return FALSE;
    }

    AcquireSRWLockShared(&g_ConfigLock);
    if (g_ConfigHasOverride && g_ConfigOverrideSni[0] != '\0')
    {
        strncpy_s(buffer, bufferLen, g_ConfigOverrideSni, _TRUNCATE);
        haveOverride = TRUE;
    }
    ReleaseSRWLockShared(&g_ConfigLock);

    if (haveOverride)
    {
        return TRUE;
    }

    return TryDeriveDefaultSni(buffer, bufferLen);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        g_hModule = (HMODULE)hinstDLL;
        if (!ProxyLoader_InitializeForCurrentModule(g_hModule))
        {
            return FALSE;
        }
        DisableThreadLibraryCalls(g_hModule);
        StartInitializationWorker();
        break;

    case DLL_PROCESS_DETACH:
#if WARPS_ENABLE_LOG_WINDOW
        g_bCanCreateLogWindow = FALSE;
#endif
        if (lpvReserved == NULL)
        {
            ShutdownModule();
        }
        break;
    }

    return TRUE;
}

static void InitializeModule(void)
{
    char processPath[MAX_PATH];
    char moduleName[MAX_PATH];
    char sni[MAX_PATH];
    BOOL tlsHooksInitialized = FALSE;

#if WARPS_ENABLE_LOG_WINDOW
#if WARPS_FORCE_FALLBACK_LOG_FILE
    g_bCanCreateLogWindow = FALSE;
    EnableFallbackLogFile();
#else
    if (IsInteractiveDebugSession())
    {
        g_bCanCreateLogWindow = TRUE;
        MaybeStartLogWindow();
    }
    else
    {
        g_bCanCreateLogWindow = FALSE;
        EnableFallbackLogFile();
    }
#endif
#endif

#if WARPS_ENABLE_LOG_WINDOW
    ResetFallbackLogFileIfTooLarge();
#endif
    GetProxyModuleName(moduleName, sizeof(moduleName));
    LogMessage("[*] WARPS v%s starting", WARPS_VERSION);
    LogMessage("[*] %s proxy loaded (PID: %lu)", moduleName, GetCurrentProcessId());
    if (!ProxyLoader_IsActive())
    {
        LogMessage("[*] proxy mode is inactive for this module");
    }
#if WARPS_ENABLE_LOG_WINDOW
    if (g_FallbackLogResetForSession)
    {
        LogMessage(
            "[*] Cleared previous log after %lu lines before starting this session",
            (unsigned long)g_PreviousFallbackLogLineCount);
    }
#endif
    if (GetModuleFileNameA(NULL, processPath, sizeof(processPath)))
    {
        LogMessage("[*] Host process: %s", processPath);
    }

#if WARPS_ENABLE_LOG_WINDOW
    if (!g_bCanCreateLogWindow)
    {
#if WARPS_FORCE_FALLBACK_LOG_FILE
        if (g_bUseFallbackLogFile && g_FallbackLogFilePath[0] != '\0')
        {
            LogMessage("[*] File logging enabled, writing logs to: %s", g_FallbackLogFilePath);
        }
        else
        {
            LogMessage("[!] File logging enabled, but no fallback log file could be opened");
        }
#else
        if (g_bUseFallbackLogFile && g_FallbackLogFilePath[0] != '\0')
        {
            LogMessage(
                "[*] Debug window unavailable in session 0, writing logs to: %s",
                g_FallbackLogFilePath);
        }
        else
        {
            LogMessage("[!] Debug window unavailable in session 0 and no fallback log file could be opened");
        }
#endif
    }
#endif

    Config_Load();
    switch (g_ConfigLoadStatus)
    {
    case CONFIG_LOAD_STATUS_OVERRIDE_LOADED:
        LogMessage("[*] Loaded SNI override from sni.txt");
        break;

    case CONFIG_LOAD_STATUS_INVALID_OVERRIDE:
        LogMessage("[!] sni.txt exists but did not contain a usable SNI override");
        break;

    case CONFIG_LOAD_STATUS_READ_ERROR:
        LogMessage("[!] sni.txt exists but could not be read");
        break;

    case CONFIG_LOAD_STATUS_PATH_ERROR:
        LogMessage("[!] Failed to resolve sni.txt next to the proxy DLL");
        break;

    case CONFIG_LOAD_STATUS_FILE_MISSING:
    case CONFIG_LOAD_STATUS_NOT_ATTEMPTED:
    default:
        break;
    }

    if (Config_CopySNI(sni, sizeof(sni)))
    {
        LogMessage("[*] Target SNI: %s", sni);
    }
    else
    {
        LogMessage("[!] Failed to resolve the effective target SNI");
    }

#if WARPS_ENABLE_LOG_WINDOW
    if (g_hLogWindow)
    {
        PostMessageA(g_hLogWindow, WM_WARPS_SYNC_SNI, 0, 0);
    }
#endif

#if WARPS_ENABLE_AWSLC_TLS_HOOKS
    if (Hooks_InitCryptoBufferNew())
    {
        tlsHooksInitialized = TRUE;
        LogMessage("[+] AWS-LC TLS SNI hooks initialized successfully");
    }
    else
    {
        LogMessage("[!] Failed to initialize AWS-LC TLS SNI hooks");
    }
#else
    LogMessage("[*] AWS-LC TLS SNI hooks disabled in this build");
#endif

#if WARPS_ENABLE_STATIC_HOSTNAME_PATCHES
    if (!tlsHooksInitialized)
    {
        if (Hooks_InitStaticHostnamePatches())
        {
            tlsHooksInitialized = TRUE;
            LogMessage("[+] Static hostname patches initialized successfully");
        }
        else
        {
            LogMessage("[*] Static hostname patching did not activate in this run");
        }
    }
    else
    {
        LogMessage("[*] Static hostname patching skipped because precise AWS-LC TLS hooks are active");
    }
#else
    LogMessage("[*] Static hostname patching disabled in this build");
#endif

#if WARPS_ENABLE_STREAM_TLS_REWRITE
    LogMessage("[*] TCP/TLS send-path rewrite enabled in this build");
#else
    LogMessage("[*] TCP/TLS send-path rewrite disabled in this build");
#endif

    g_bTlsHooksInitialized = tlsHooksInitialized;

    if (UdpHooks_Init())
    {
        g_bUdpHooksInitialized = TRUE;
        LogMessage("[+] UDP QUIC hooks initialized successfully");
    }
    else
    {
        g_bUdpHooksInitialized = FALSE;
        LogMessage("[!] Failed to initialize UDP QUIC hooks");
    }

    if (!g_bTlsHooksInitialized && !g_bUdpHooksInitialized)
    {
        LogMessage("[!] No active SNI rewrite path was initialized");
    }
}

static void StartInitializationWorker(void)
{
    InitializeModule();
}

static void ShutdownModule(void)
{
    char moduleName[MAX_PATH];

    GetProxyModuleName(moduleName, sizeof(moduleName));
    LogMessage("[*] %s proxy unloading", moduleName);

    if (g_bUdpHooksInitialized)
    {
        UdpHooks_Cleanup();
        g_bUdpHooksInitialized = FALSE;
    }

    if (g_bTlsHooksInitialized)
    {
        Hooks_Cleanup();
        g_bTlsHooksInitialized = FALSE;
    }

#if WARPS_ENABLE_LOG_WINDOW
    if (g_hLogWindow)
    {
        PostMessageA(g_hLogWindow, WM_CLOSE, 0, 0);
    }
#endif

    ProxyLoader_CleanupForCurrentModule();
}

static void GetProxyModuleName(char* buffer, size_t bufferLength)
{
    char modulePath[MAX_PATH];
    char* lastSlash;

    if (!buffer || bufferLength == 0)
    {
        return;
    }

    buffer[0] = '\0';
    if (!g_hModule ||
        !GetModuleFileNameA(g_hModule, modulePath, sizeof(modulePath)))
    {
        strncpy_s(buffer, bufferLength, "WARPS", _TRUNCATE);
        return;
    }

    lastSlash = strrchr(modulePath, '\\');
    strncpy_s(
        buffer,
        bufferLength,
        lastSlash ? (lastSlash + 1) : modulePath,
        _TRUNCATE);
}

void LogMessage(const char* format, ...)
{
    (void)format;
}

#ifdef __cplusplus
}
#endif
