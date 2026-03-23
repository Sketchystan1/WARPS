#ifdef __cplusplus
extern "C" {
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hooks.h"
#include "config.h"

extern void LogMessage(const char* format, ...);

typedef BOOL (WINAPI* PFN_K32_ENUM_PROCESS_MODULES)(
    HANDLE process,
    HMODULE* modules,
    DWORD cb,
    LPDWORD needed);
typedef DWORD (WINAPI* PFN_K32_GET_MODULE_FILE_NAME_EX_A)(
    HANDLE process,
    HMODULE module,
    LPSTR fileName,
    DWORD size);

static PFN_K32_ENUM_PROCESS_MODULES g_pK32EnumProcessModules = NULL;
static PFN_K32_GET_MODULE_FILE_NAME_EX_A g_pK32GetModuleFileNameExA = NULL;

static BOOL EnsureKernel32ModuleEnumFunctions(void)
{
    HMODULE kernel32Module;

    if (g_pK32EnumProcessModules && g_pK32GetModuleFileNameExA)
    {
        return TRUE;
    }

    kernel32Module = GetModuleHandleA("kernel32.dll");
    if (!kernel32Module)
    {
        return FALSE;
    }

    if (!g_pK32EnumProcessModules)
    {
        g_pK32EnumProcessModules = (PFN_K32_ENUM_PROCESS_MODULES)GetProcAddress(
            kernel32Module,
            "K32EnumProcessModules");
    }

    if (!g_pK32GetModuleFileNameExA)
    {
        g_pK32GetModuleFileNameExA = (PFN_K32_GET_MODULE_FILE_NAME_EX_A)GetProcAddress(
            kernel32Module,
            "K32GetModuleFileNameExA");
    }

    return g_pK32EnumProcessModules != NULL &&
           g_pK32GetModuleFileNameExA != NULL;
}

static BOOL WARPSEnumProcessModules(
    HANDLE process,
    HMODULE* modules,
    DWORD cb,
    LPDWORD needed)
{
    if (!EnsureKernel32ModuleEnumFunctions())
    {
        return FALSE;
    }

    return g_pK32EnumProcessModules(process, modules, cb, needed);
}

static DWORD WARPSGetModuleFileNameExA(
    HANDLE process,
    HMODULE module,
    LPSTR fileName,
    DWORD size)
{
    if (!fileName || size == 0)
    {
        return 0;
    }

    if (EnsureKernel32ModuleEnumFunctions())
    {
        return g_pK32GetModuleFileNameExA(process, module, fileName, size);
    }

    if (process == GetCurrentProcess())
    {
        return GetModuleFileNameA(module, fileName, size);
    }

    fileName[0] = '\0';
    return 0;
}

static HMODULE g_hTargetModule = NULL;

#ifdef _WIN64
#define JUMP_SIZE 14
#else
#define JUMP_SIZE 5
#endif

#define TRAMPOLINE_SIZE (JUMP_SIZE * 2)
#define HOOK_INIT_RETRY_COUNT 50
#define HOOK_INIT_RETRY_DELAY_MS 200
#define HOOK_TRACE_INITIAL_SAMPLES 8
#define HOOK_TRACE_INTERVAL 250
#define HOSTNAME_LIKE_MIN_LENGTH 8
#define MAX_STATIC_HOSTNAME_OCCURRENCES 16
#define MAX_STATIC_HOSTNAME_MATCHES 64
#define MAX_STATIC_CODE_PATCH_BLOCK_LEAS 8
#define STATIC_CODE_PATCH_WINDOW_BEFORE 16
#define STATIC_CODE_PATCH_WINDOW_AFTER 8
#define RIP_RELATIVE_LEA_SIZE 7
#define MAX_RIP_RELATIVE_REACH 0x7fff0000ULL

#ifndef WARPS_ENABLE_AWSLC_CBB_HOOKS
#define WARPS_ENABLE_AWSLC_CBB_HOOKS 0
#endif

#define TLS_RECORD_HEADER_SIZE 5
#define TLS_HANDSHAKE_HEADER_SIZE 4
#define TLS_CLIENT_HELLO_FIXED_SIZE 34
#define TLS_RECORD_TYPE_HANDSHAKE 22
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define TLS_EXTENSION_TYPE_SERVER_NAME 0
#define TLS_SNI_NAME_TYPE_HOST_NAME 0

typedef struct WARP_KNOWN_SNI_TAG
{
    const char* value;
    size_t length;
} WARP_KNOWN_SNI;

static const WARP_KNOWN_SNI g_KnownWARPSs[] = {
    { "consumer-masque.cloudflareclient.com", 36 },
    { "consumer-masque.cloudflareclient.com.", 37 },
    { "consumer-masque-proxy.cloudflareclient.com", 42 },
    { "consumer-masque-proxy.cloudflareclient.com.", 43 },
    { "zt-masque.cloudflareclient.com", 30 },
    { "zt-masque.cloudflareclient.com.", 31 },
    { "zt-masque-proxy.cloudflareclient.com", 36 },
    { "zt-masque-proxy.cloudflareclient.com.", 37 }
};

typedef struct cbs_st
{
    const unsigned char* data;
    size_t len;
} CBS;

typedef struct cbb_st CBB;

typedef void* (__cdecl* CRYPTO_BUFFER_new_TYPE)(
    const unsigned char* data,
    size_t len,
    void* pool);

typedef void* (__cdecl* CRYPTO_BUFFER_new_from_CBS_TYPE)(
    const CBS* cbs,
    void* pool);

typedef int (__cdecl* CBB_add_bytes_TYPE)(
    CBB* cbb,
    const unsigned char* data,
    size_t len);

typedef int (__cdecl* CBB_finish_TYPE)(
    CBB* cbb,
    unsigned char** out_data,
    size_t* out_len);

typedef struct HOOK_CANDIDATE_CONFIG_TAG
{
    const char* label;
    const char* exactName;
    const char* suffix;
    void* detour;
    void** originalStorage;
} HOOK_CANDIDATE_CONFIG;

typedef struct HOOK_SLOT_TAG
{
    const HOOK_CANDIDATE_CONFIG* config;
    unsigned char originalBytes[16];
    unsigned char* target;
    void* trampoline;
    HMODULE module;
    BOOL installed;
    char resolvedName[128];
} HOOK_SLOT;

static CRYPTO_BUFFER_new_TYPE g_pfnOriginalCryptoBufferNew = NULL;
static CRYPTO_BUFFER_new_TYPE g_pfnOriginalCryptoBufferNewFromStaticDataUnsafe = NULL;
static CRYPTO_BUFFER_new_from_CBS_TYPE g_pfnOriginalCryptoBufferNewFromCbs = NULL;
static CBB_add_bytes_TYPE g_pfnOriginalCbbAddBytes = NULL;
static CBB_finish_TYPE g_pfnOriginalCbbFinish = NULL;
static char* g_pStaticReplacementSni = NULL;
static SIZE_T g_StaticReplacementSniLength = 0;
static BOOL g_StaticReplacementSniUsesVirtualAlloc = FALSE;

#define MAX_STATIC_PATCHED_SITES 1024
static uintptr_t g_PatchedLeas[MAX_STATIC_PATCHED_SITES];
static DWORD g_PatchedLeaCount = 0;
static uintptr_t g_PatchedLengths[MAX_STATIC_PATCHED_SITES];
static DWORD g_PatchedLengthCount = 0;
static uintptr_t g_PatchedStringRefs[MAX_STATIC_PATCHED_SITES];
static DWORD g_PatchedStringRefCount = 0;
static DWORD g_StaticHostnamePatchCount = 0;

static volatile LONG g_CryptoBufferNewHitCount = 0;
static volatile LONG g_CryptoBufferNewFromCbsHitCount = 0;
static volatile LONG g_CryptoBufferNewFromStaticDataUnsafeHitCount = 0;
static volatile LONG g_CbbAddBytesHitCount = 0;
static volatile LONG g_CbbFinishHitCount = 0;

static void* __cdecl Hooked_CRYPTO_BUFFER_new(
    const unsigned char* data,
    size_t len,
    void* pool);
static void* __cdecl Hooked_CRYPTO_BUFFER_new_from_static_data_unsafe(
    const unsigned char* data,
    size_t len,
    void* pool);
static void* __cdecl Hooked_CRYPTO_BUFFER_new_from_CBS(
    const CBS* cbs,
    void* pool);
static int __cdecl Hooked_CBB_add_bytes(
    CBB* cbb,
    const unsigned char* data,
    size_t len);
static int __cdecl Hooked_CBB_finish(
    CBB* cbb,
    unsigned char** out_data,
    size_t* out_len);
static const HOOK_CANDIDATE_CONFIG g_HookCandidateConfigs[] = {
    {
        "CRYPTO_BUFFER_new",
        "CRYPTO_BUFFER_new",
        "_CRYPTO_BUFFER_new",
        (void*)&Hooked_CRYPTO_BUFFER_new,
        (void**)&g_pfnOriginalCryptoBufferNew
    },
    {
        "CRYPTO_BUFFER_new_from_CBS",
        "CRYPTO_BUFFER_new_from_CBS",
        "_CRYPTO_BUFFER_new_from_CBS",
        (void*)&Hooked_CRYPTO_BUFFER_new_from_CBS,
        (void**)&g_pfnOriginalCryptoBufferNewFromCbs
    },
    {
        "CRYPTO_BUFFER_new_from_static_data_unsafe",
        "CRYPTO_BUFFER_new_from_static_data_unsafe",
        "_CRYPTO_BUFFER_new_from_static_data_unsafe",
        (void*)&Hooked_CRYPTO_BUFFER_new_from_static_data_unsafe,
        (void**)&g_pfnOriginalCryptoBufferNewFromStaticDataUnsafe
    },
    {
        "CBB_add_bytes",
        "CBB_add_bytes",
        "_CBB_add_bytes",
        (void*)&Hooked_CBB_add_bytes,
        (void**)&g_pfnOriginalCbbAddBytes
    },
    {
        "CBB_finish",
        "CBB_finish",
        "_CBB_finish",
        (void*)&Hooked_CBB_finish,
        (void**)&g_pfnOriginalCbbFinish
    }
};

static HOOK_SLOT g_HookSlots[
    sizeof(g_HookCandidateConfigs) / sizeof(g_HookCandidateConfigs[0])] = { 0 };
static DWORD g_InstalledHookCount = 0;

typedef struct TLS_SNI_LOCATION_TAG
{
    SIZE_T extensionsLengthOffset;
    SIZE_T extensionLengthOffset;
    SIZE_T serverNameListLengthOffset;
    SIZE_T serverNameLengthOffset;
    SIZE_T serverNameOffset;
    WORD extensionsLength;
    WORD extensionLength;
    WORD serverNameListLength;
    WORD serverNameLength;
} TLS_SNI_LOCATION;

typedef struct STATIC_HOSTNAME_MATCH_TAG
{
    const unsigned char* address;
    const WARP_KNOWN_SNI* knownSni;
} STATIC_HOSTNAME_MATCH;

typedef struct STATIC_CODE_PATCH_SITE_TAG
{
    SIZE_T leaOffsets[4];
    SIZE_T lengthOffsets[3];
} STATIC_CODE_PATCH_SITE;

static const STATIC_CODE_PATCH_SITE g_StaticCodePatchSites[] = {
    {
        { 0x135FD78, 0x135FD7F, 0x135FD9B, 0x135FDA2 },
        { 0x135FD6A, 0x135FD6F, 0x135FD91 }
    }
};

static WORD ReadUInt16BE(const unsigned char* data)
{
    return (WORD)(((WORD)data[0] << 8) | data[1]);
}

static DWORD ReadUInt24BE(const unsigned char* data)
{
    return ((DWORD)data[0] << 16) | ((DWORD)data[1] << 8) | data[2];
}

static void WriteUInt16BE(unsigned char* data, WORD value)
{
    data[0] = (unsigned char)((value >> 8) & 0xFF);
    data[1] = (unsigned char)(value & 0xFF);
}

static void WriteUInt24BE(unsigned char* data, DWORD value)
{
    data[0] = (unsigned char)((value >> 16) & 0xFF);
    data[1] = (unsigned char)((value >> 8) & 0xFF);
    data[2] = (unsigned char)(value & 0xFF);
}

static BOOL HasRange(SIZE_T offset, SIZE_T length, SIZE_T limit)
{
    return offset <= limit && length <= limit - offset;
}

static BOOL TryCopySniBytes(
    const unsigned char* sniData,
    SIZE_T sniLen,
    char* sni,
    size_t sniCapacity)
{
    SIZE_T copyLen;

    if (!sniData || !sni || sniCapacity == 0 || sniLen == 0)
    {
        return FALSE;
    }

    copyLen = sniLen;
    if (copyLen >= sniCapacity)
    {
        copyLen = sniCapacity - 1;
    }

    memcpy(sni, sniData, copyLen);
    sni[copyLen] = '\0';
    return TRUE;
}

static BOOL IsHostnameLikeCharacter(unsigned char value)
{
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') ||
           value == '.' ||
           value == '-';
}

static BOOL TryCopyHostnameLikeBytes(
    const unsigned char* data,
    SIZE_T len,
    char* text,
    size_t textCapacity)
{
    SIZE_T index;
    BOOL hasAlpha = FALSE;
    BOOL hasDot = FALSE;

    if (!data || !text || textCapacity == 0 || len < HOSTNAME_LIKE_MIN_LENGTH || len >= textCapacity)
    {
        return FALSE;
    }

    for (index = 0; index < len; ++index)
    {
        unsigned char value = data[index];

        if (!IsHostnameLikeCharacter(value))
        {
            return FALSE;
        }

        if ((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z'))
        {
            hasAlpha = TRUE;
        }

        if (value == '.')
        {
            hasDot = TRUE;
        }
    }

    if (!hasAlpha || !hasDot)
    {
        return FALSE;
    }

    return TryCopySniBytes(data, len, text, textCapacity);
}

static LONG RegisterHookHit(volatile LONG* counter)
{
    if (!counter)
    {
        return 0;
    }

    return InterlockedIncrement(counter);
}

static BOOL ShouldLogHookSample(LONG hitCount)
{
    return hitCount > 0 &&
           (hitCount <= HOOK_TRACE_INITIAL_SAMPLES ||
            (hitCount % HOOK_TRACE_INTERVAL) == 0);
}

static void LogHookHitSample(
    const char* hookLabel,
    LONG hitCount,
    const unsigned char* data,
    SIZE_T len)
{
    char hostnameLikeValue[MAX_PATH];

    if (!hookLabel || !data || len == 0)
    {
        return;
    }

    if (TryCopyHostnameLikeBytes(data, len, hostnameLikeValue, sizeof(hostnameLikeValue)))
    {
        LogMessage(
            "[*] %s hit #%ld saw hostname-like bytes (%u bytes): %s",
            hookLabel,
            hitCount,
            (unsigned int)len,
            hostnameLikeValue);
        return;
    }

    if (!ShouldLogHookSample(hitCount))
    {
        return;
    }

    LogMessage(
        "[*] %s hit #%ld with %u bytes (first byte 0x%02X)",
        hookLabel,
        hitCount,
        (unsigned int)len,
        data[0]);
}

static BOOL TryApplyDeltaToSize(SIZE_T base, SSIZE_T delta, SIZE_T* result)
{
    if (!result)
    {
        return FALSE;
    }

    if (delta >= 0)
    {
        if (base > ((SIZE_T)-1) - (SIZE_T)delta)
        {
            return FALSE;
        }

        *result = base + (SIZE_T)delta;
        return TRUE;
    }

    if ((SIZE_T)(-delta) > base)
    {
        return FALSE;
    }

    *result = base - (SIZE_T)(-delta);
    return TRUE;
}

static void WriteJumpInstruction(unsigned char* source, const void* destination)
{
#ifdef _WIN64
    unsigned char jumpCode[JUMP_SIZE] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    unsigned long long address = (unsigned long long)destination;
    memcpy(&jumpCode[6], &address, sizeof(address));
    memcpy(source, jumpCode, sizeof(jumpCode));
#else
    unsigned char jumpCode[JUMP_SIZE];
    DWORD offset = (DWORD)((const unsigned char*)destination - source - JUMP_SIZE);
    jumpCode[0] = 0xE9;
    memcpy(&jumpCode[1], &offset, sizeof(offset));
    memcpy(source, jumpCode, sizeof(jumpCode));
#endif
}

static void ResetHookSlot(HOOK_SLOT* slot)
{
    if (!slot)
    {
        return;
    }

    memset(slot->originalBytes, 0, sizeof(slot->originalBytes));
    slot->target = NULL;
    slot->trampoline = NULL;
    slot->module = NULL;
    slot->installed = FALSE;
    slot->resolvedName[0] = '\0';
}

static BOOL GetModuleImageLayout(
    HMODULE module,
    const unsigned char** imageBase,
    SIZE_T* imageSize,
    const IMAGE_NT_HEADERS** ntHeaders)
{
    const unsigned char* base = (const unsigned char*)module;
    const IMAGE_DOS_HEADER* dosHeader;
    const IMAGE_NT_HEADERS* discoveredNtHeaders;

    if (!module)
    {
        return FALSE;
    }

    dosHeader = (const IMAGE_DOS_HEADER*)base;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }

    discoveredNtHeaders = (const IMAGE_NT_HEADERS*)(base + dosHeader->e_lfanew);
    if (discoveredNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }

    if (imageBase)
    {
        *imageBase = base;
    }

    if (imageSize)
    {
        *imageSize = discoveredNtHeaders->OptionalHeader.SizeOfImage;
    }

    if (ntHeaders)
    {
        *ntHeaders = discoveredNtHeaders;
    }

    return TRUE;
}

static BOOL IsNonExecutableDataSection(const IMAGE_SECTION_HEADER* section)
{
    if (!section)
    {
        return FALSE;
    }

    return section->Misc.VirtualSize > 0 &&
           (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 &&
           ((section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 ||
            (section->Characteristics & IMAGE_SCN_MEM_WRITE) != 0);
}

static BOOL IsExecutableSection(const IMAGE_SECTION_HEADER* section)
{
    return section &&
           section->Misc.VirtualSize > 0 &&
           (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

static void ReleaseStaticReplacementSniBuffer(void)
{
    if (!g_pStaticReplacementSni)
    {
        return;
    }

    if (g_StaticReplacementSniUsesVirtualAlloc)
    {
        VirtualFree(g_pStaticReplacementSni, 0, MEM_RELEASE);
    }
    else
    {
        free(g_pStaticReplacementSni);
    }

    g_pStaticReplacementSni = NULL;
    g_StaticReplacementSniLength = 0;
    g_StaticReplacementSniUsesVirtualAlloc = FALSE;
}

static void* AllocateNearAddress(uintptr_t nearAddress, SIZE_T size)
{
    SYSTEM_INFO systemInfo;
    SIZE_T pageSize;
    SIZE_T granularity;
    SIZE_T alignedSize;
    uintptr_t alignedAddress;
    uintptr_t minAddress;
    uintptr_t maxAddress;
    SIZE_T delta;

    if (size == 0)
    {
        return NULL;
    }

    GetSystemInfo(&systemInfo);
    pageSize = systemInfo.dwPageSize ? systemInfo.dwPageSize : 0x1000;
    granularity = systemInfo.dwAllocationGranularity ? systemInfo.dwAllocationGranularity : pageSize;
    alignedSize = (size + pageSize - 1) & ~(pageSize - 1);
    alignedAddress = nearAddress & ~(granularity - 1);
    minAddress = nearAddress > MAX_RIP_RELATIVE_REACH
        ? nearAddress - MAX_RIP_RELATIVE_REACH
        : 0;
    maxAddress = nearAddress < (uintptr_t)-1 - MAX_RIP_RELATIVE_REACH
        ? nearAddress + MAX_RIP_RELATIVE_REACH
        : (uintptr_t)-1;

    for (delta = 0; delta < MAX_RIP_RELATIVE_REACH; delta += granularity)
    {
        uintptr_t candidateAbove = alignedAddress + delta;

        if (candidateAbove >= minAddress && candidateAbove <= maxAddress)
        {
            void* allocation = VirtualAlloc(
                (LPVOID)candidateAbove,
                alignedSize,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE);
            if (allocation)
            {
                return allocation;
            }
        }

        if (delta != 0 && alignedAddress >= delta)
        {
            uintptr_t candidateBelow = alignedAddress - delta;

            if (candidateBelow >= minAddress && candidateBelow <= maxAddress)
            {
                void* allocation = VirtualAlloc(
                    (LPVOID)candidateBelow,
                    alignedSize,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE);
                if (allocation)
                {
                    return allocation;
                }
            }
        }
    }

    return NULL;
}

static BOOL EnsureStaticReplacementSniBuffer(HMODULE preferredModule, const char* replacementSni)
{
    size_t replacementLength;
    char* replacementCopy;
    const unsigned char* imageBase = NULL;
    SIZE_T imageSize = 0;
    BOOL usedVirtualAlloc = FALSE;

    if (!replacementSni || !replacementSni[0])
    {
        return FALSE;
    }

    replacementLength = strlen(replacementSni);
    if (g_pStaticReplacementSni &&
        g_StaticReplacementSniLength == replacementLength &&
        strcmp(g_pStaticReplacementSni, replacementSni) == 0)
    {
        return TRUE;
    }

    if (preferredModule &&
        GetModuleImageLayout(preferredModule, &imageBase, &imageSize, NULL) &&
        imageBase &&
        imageSize > 0)
    {
        replacementCopy = (char*)AllocateNearAddress(
            (uintptr_t)imageBase + imageSize,
            replacementLength + 1);
        usedVirtualAlloc = replacementCopy != NULL;
    }
    else
    {
        replacementCopy = NULL;
    }

    if (!replacementCopy)
    {
        replacementCopy = (char*)malloc(replacementLength + 1);
        usedVirtualAlloc = FALSE;
    }

    if (!replacementCopy)
    {
        LogMessage("[!] Failed to allocate static replacement SNI buffer");
        return FALSE;
    }

    ReleaseStaticReplacementSniBuffer();
    memcpy(replacementCopy, replacementSni, replacementLength + 1);
    g_pStaticReplacementSni = replacementCopy;
    g_StaticReplacementSniLength = replacementLength;
    g_StaticReplacementSniUsesVirtualAlloc = usedVirtualAlloc;
    return TRUE;
}

static SIZE_T CollectStaticHostnameOccurrences(
    HMODULE module,
    const char* hostname,
    const unsigned char** occurrences,
    SIZE_T maxOccurrences)
{
    const unsigned char* imageBase;
    const IMAGE_NT_HEADERS* ntHeaders;
    const IMAGE_SECTION_HEADER* sections;
    SIZE_T hostnameLength;
    SIZE_T matchCount = 0;
    WORD sectionIndex;

    if (!module || !hostname || !occurrences || maxOccurrences == 0)
    {
        return 0;
    }

    if (!GetModuleImageLayout(module, &imageBase, NULL, &ntHeaders))
    {
        return 0;
    }

    hostnameLength = strlen(hostname);
    sections = IMAGE_FIRST_SECTION(ntHeaders);
    for (sectionIndex = 0; sectionIndex < ntHeaders->FileHeader.NumberOfSections; ++sectionIndex)
    {
        const IMAGE_SECTION_HEADER* section = &sections[sectionIndex];
        const unsigned char* sectionBase;
        SIZE_T sectionSize;
        SIZE_T offset;

        if (!IsNonExecutableDataSection(section))
        {
            continue;
        }

        sectionBase = imageBase + section->VirtualAddress;
        sectionSize = section->Misc.VirtualSize;
        if (sectionSize < hostnameLength || hostnameLength == 0)
        {
            continue;
        }

        for (offset = 0; offset <= sectionSize - hostnameLength; ++offset)
        {
            if (memcmp(sectionBase + offset, hostname, hostnameLength) == 0)
            {
                occurrences[matchCount++] = sectionBase + offset;
                if (matchCount >= maxOccurrences)
                {
                    return matchCount;
                }
            }
        }
    }

    return matchCount;
}

static BOOL MatchesStaticHostnameOccurrence(
    uintptr_t candidateAddress,
    const unsigned char* const* occurrences,
    SIZE_T occurrenceCount)
{
    SIZE_T index;

    for (index = 0; index < occurrenceCount; ++index)
    {
        if (candidateAddress == (uintptr_t)occurrences[index])
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL PatchRustStringReference(
    unsigned char* referenceLocation,
    const char* replacementSni,
    SIZE_T replacementLength)
{
    DWORD oldProtect;
    uintptr_t replacementAddress = (uintptr_t)replacementSni;

    if (!referenceLocation || !replacementSni || replacementLength == 0)
    {
        return FALSE;
    }

    if (!VirtualProtect(
            referenceLocation,
            sizeof(replacementAddress) + sizeof(replacementLength),
            PAGE_READWRITE,
            &oldProtect))
    {
        LogMessage("[!] VirtualProtect failed while patching a static hostname reference: %lu", GetLastError());
        return FALSE;
    }

    memcpy(referenceLocation, &replacementAddress, sizeof(replacementAddress));
    memcpy(referenceLocation + sizeof(replacementAddress), &replacementLength, sizeof(replacementLength));

    VirtualProtect(
        referenceLocation,
        sizeof(replacementAddress) + sizeof(replacementLength),
        oldProtect,
        &oldProtect);
    FlushInstructionCache(
        GetCurrentProcess(),
        referenceLocation,
        sizeof(replacementAddress) + sizeof(replacementLength));

    if (g_PatchedStringRefCount < MAX_STATIC_PATCHED_SITES)
    {
        g_PatchedStringRefs[g_PatchedStringRefCount++] = (uintptr_t)referenceLocation;
    }

    return TRUE;
}

static SIZE_T CollectStaticHostnameMatches(
    HMODULE module,
    STATIC_HOSTNAME_MATCH* matches,
    SIZE_T maxMatches)
{
    SIZE_T totalMatches = 0;
    DWORD knownSniIndex;

    if (!module || !matches || maxMatches == 0)
    {
        return 0;
    }

    for (knownSniIndex = 0;
         knownSniIndex < sizeof(g_KnownWARPSs) / sizeof(g_KnownWARPSs[0]);
         ++knownSniIndex)
    {
        const WARP_KNOWN_SNI* knownSni = &g_KnownWARPSs[knownSniIndex];
        const unsigned char* occurrences[MAX_STATIC_HOSTNAME_OCCURRENCES];
        SIZE_T occurrenceCount = CollectStaticHostnameOccurrences(
            module,
            knownSni->value,
            occurrences,
            sizeof(occurrences) / sizeof(occurrences[0]));
        SIZE_T occurrenceIndex;

        for (occurrenceIndex = 0;
             occurrenceIndex < occurrenceCount && totalMatches < maxMatches;
             ++occurrenceIndex)
        {
            matches[totalMatches].address = occurrences[occurrenceIndex];
            matches[totalMatches].knownSni = knownSni;
            totalMatches++;
        }
    }

    return totalMatches;
}

static const WARP_KNOWN_SNI* FindKnownHostnameMatchByAddress(
    uintptr_t candidateAddress,
    const STATIC_HOSTNAME_MATCH* matches,
    SIZE_T matchCount)
{
    SIZE_T matchIndex;

    for (matchIndex = 0; matchIndex < matchCount; ++matchIndex)
    {
        if (candidateAddress == (uintptr_t)matches[matchIndex].address)
        {
            return matches[matchIndex].knownSni;
        }
    }

    return NULL;
}

static BOOL TryResolveRipRelativeLeaTarget(
    const unsigned char* instruction,
    uintptr_t instructionAddress,
    uintptr_t* targetAddress)
{
    LONG displacement;

    if (!instruction || !targetAddress)
    {
        return FALSE;
    }

    if ((instruction[0] != 0x48 &&
         instruction[0] != 0x49 &&
         instruction[0] != 0x4C &&
         instruction[0] != 0x4D) ||
        instruction[1] != 0x8D)
    {
        return FALSE;
    }

    switch (instruction[2])
    {
    case 0x05:
    case 0x0D:
    case 0x15:
    case 0x1D:
    case 0x25:
    case 0x2D:
    case 0x35:
    case 0x3D:
        break;
    default:
        return FALSE;
    }

    memcpy(&displacement, instruction + 3, sizeof(displacement));
    *targetAddress = instructionAddress + RIP_RELATIVE_LEA_SIZE + (LONG_PTR)displacement;
    return TRUE;
}

static BOOL PatchRipRelativeLeaInstruction(
    unsigned char* instruction,
    void* newTarget)
{
    DWORD oldProtect;
    LONG displacement;
    LONG_PTR displacement64;

    if (!instruction || !newTarget)
    {
        return FALSE;
    }

    displacement64 = (LONG_PTR)((unsigned char*)newTarget - (instruction + RIP_RELATIVE_LEA_SIZE));
    if (displacement64 < LONG_MIN || displacement64 > LONG_MAX)
    {
        LogMessage("[!] Replacement SNI buffer is out of RIP-relative range for a static code patch");
        return FALSE;
    }

    displacement = (LONG)displacement64;
    if (!VirtualProtect(instruction, RIP_RELATIVE_LEA_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        LogMessage("[!] VirtualProtect failed while patching a static code hostname reference: %lu", GetLastError());
        return FALSE;
    }

    memcpy(instruction + 3, &displacement, sizeof(displacement));
    VirtualProtect(instruction, RIP_RELATIVE_LEA_SIZE, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), instruction, RIP_RELATIVE_LEA_SIZE);

    if (g_PatchedLeaCount < MAX_STATIC_PATCHED_SITES)
    {
        g_PatchedLeas[g_PatchedLeaCount++] = (uintptr_t)instruction;
    }

    return TRUE;
}

static DWORD PatchKnownLengthImmediatesInRange(
    unsigned char* rangeStart,
    SIZE_T rangeLength,
    SIZE_T replacementLength)
{
    DWORD patchedCount = 0;
    SIZE_T offset;
    DWORD replacementLength32;

    if (!rangeStart || rangeLength < 5 || replacementLength > 0xFFFFFFFFu)
    {
        return 0;
    }

    replacementLength32 = (DWORD)replacementLength;
    for (offset = 0; offset + 5 <= rangeLength; ++offset)
    {
        DWORD currentValue;
        DWORD oldProtect;

        if (rangeStart[offset] >= 0xB8 && rangeStart[offset] <= 0xBF)
        {
            memcpy(&currentValue, rangeStart + offset + 1, sizeof(currentValue));
            if (currentValue != 0x1E && currentValue != 0x24 && currentValue != 0x2A)
            {
                continue;
            }

            if (!VirtualProtect(rangeStart + offset, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                continue;
            }

            memcpy(rangeStart + offset + 1, &replacementLength32, sizeof(replacementLength32));
            VirtualProtect(rangeStart + offset, 5, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), rangeStart + offset, 5);

            if (g_PatchedLengthCount < MAX_STATIC_PATCHED_SITES)
            {
                g_PatchedLengths[g_PatchedLengthCount++] = (uintptr_t)(rangeStart + offset);
            }

            patchedCount++;
            offset += 4;
            continue;
        }

        if (offset + 6 <= rangeLength &&
            rangeStart[offset] == 0x41 &&
            rangeStart[offset + 1] >= 0xB8 &&
            rangeStart[offset + 1] <= 0xBF)
        {
            memcpy(&currentValue, rangeStart + offset + 2, sizeof(currentValue));
            if (currentValue != 0x1E && currentValue != 0x24 && currentValue != 0x2A)
            {
                continue;
            }

            if (!VirtualProtect(rangeStart + offset, 6, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                continue;
            }

            memcpy(rangeStart + offset + 2, &replacementLength32, sizeof(replacementLength32));
            VirtualProtect(rangeStart + offset, 6, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), rangeStart + offset, 6);

            if (g_PatchedLengthCount < MAX_STATIC_PATCHED_SITES)
            {
                g_PatchedLengths[g_PatchedLengthCount++] = (uintptr_t)(rangeStart + offset);
            }

            patchedCount++;
            offset += 5;
        }
    }

    return patchedCount;
}

static BOOL PatchKnownLengthImmediateInstruction(
    unsigned char* instruction,
    SIZE_T replacementLength)
{
    DWORD oldProtect;
    DWORD replacementLength32;
    DWORD currentValue;
    SIZE_T instructionSize;
    SIZE_T immediateOffset;

    if (!instruction || replacementLength > 0xFFFFFFFFu)
    {
        return FALSE;
    }

    if (instruction[0] >= 0xB8 && instruction[0] <= 0xBF)
    {
        instructionSize = 5;
        immediateOffset = 1;
    }
    else if (instruction[0] == 0x41 &&
             instruction[1] >= 0xB8 &&
             instruction[1] <= 0xBF)
    {
        instructionSize = 6;
        immediateOffset = 2;
    }
    else
    {
        return FALSE;
    }

    memcpy(&currentValue, instruction + immediateOffset, sizeof(currentValue));
    if (currentValue != 0x1E && currentValue != 0x24 && currentValue != 0x2A)
    {
        return FALSE;
    }

    replacementLength32 = (DWORD)replacementLength;
    if (!VirtualProtect(instruction, instructionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        return FALSE;
    }

    memcpy(instruction + immediateOffset, &replacementLength32, sizeof(replacementLength32));
    VirtualProtect(instruction, instructionSize, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), instruction, instructionSize);

    if (g_PatchedLengthCount < MAX_STATIC_PATCHED_SITES)
    {
        g_PatchedLengths[g_PatchedLengthCount++] = (uintptr_t)instruction;
    }

    return TRUE;
}

static DWORD PatchStaticWarpHostnameSelectionCode(
    HMODULE module,
    const char* replacementSni)
{
    const unsigned char* imageBase;
    const IMAGE_NT_HEADERS* ntHeaders;
    const IMAGE_SECTION_HEADER* sections;
    STATIC_HOSTNAME_MATCH matches[MAX_STATIC_HOSTNAME_MATCHES];
    SIZE_T matchCount;
    DWORD totalPatchedBlocks = 0;
    DWORD totalPatchedLeas = 0;
    DWORD totalPatchedLengths = 0;
    WORD sectionIndex;

    if (!module || !replacementSni || !replacementSni[0])
    {
        return 0;
    }

    if (!g_pStaticReplacementSni ||
        _stricmp(g_pStaticReplacementSni, replacementSni) != 0)
    {
        if (!EnsureStaticReplacementSniBuffer(module, replacementSni))
        {
            return 0;
        }
    }

    if (!GetModuleImageLayout(module, &imageBase, NULL, &ntHeaders))
    {
        return 0;
    }

    matchCount = CollectStaticHostnameMatches(
        module,
        matches,
        sizeof(matches) / sizeof(matches[0]));
    if (matchCount == 0)
    {
        return 0;
    }

    {
        DWORD patchedFastBlocks = 0;
        DWORD siteIndex;

        for (siteIndex = 0;
             siteIndex < sizeof(g_StaticCodePatchSites) / sizeof(g_StaticCodePatchSites[0]);
             ++siteIndex)
        {
            const STATIC_CODE_PATCH_SITE* site = &g_StaticCodePatchSites[siteIndex];
            SIZE_T leaIndex;
            SIZE_T lengthIndex;
            DWORD patchedLeas = 0;
            DWORD patchedLengths = 0;
            BOOL siteMatches = TRUE;

            for (leaIndex = 0; leaIndex < sizeof(site->leaOffsets) / sizeof(site->leaOffsets[0]); ++leaIndex)
            {
                unsigned char* instruction = (unsigned char*)imageBase + site->leaOffsets[leaIndex];
                uintptr_t targetAddress;

                if (site->leaOffsets[leaIndex] + RIP_RELATIVE_LEA_SIZE > ntHeaders->OptionalHeader.SizeOfImage ||
                    !TryResolveRipRelativeLeaTarget(
                        instruction,
                        (uintptr_t)instruction,
                        &targetAddress) ||
                    !FindKnownHostnameMatchByAddress(targetAddress, matches, matchCount))
                {
                    siteMatches = FALSE;
                    break;
                }
            }

            if (!siteMatches)
            {
                continue;
            }

            for (leaIndex = 0; leaIndex < sizeof(site->leaOffsets) / sizeof(site->leaOffsets[0]); ++leaIndex)
            {
                if (PatchRipRelativeLeaInstruction(
                        (unsigned char*)imageBase + site->leaOffsets[leaIndex],
                        g_pStaticReplacementSni))
                {
                    patchedLeas++;
                }
            }

            for (lengthIndex = 0;
                 lengthIndex < sizeof(site->lengthOffsets) / sizeof(site->lengthOffsets[0]);
                 ++lengthIndex)
            {
                if (PatchKnownLengthImmediateInstruction(
                        (unsigned char*)imageBase + site->lengthOffsets[lengthIndex],
                        g_StaticReplacementSniLength))
                {
                    patchedLengths++;
                }
            }

            if (patchedLeas > 0)
            {
                patchedFastBlocks++;
                LogMessage(
                    "[+] Patched static hostname code block at %p (%lu LEA references, %lu length immediates)",
                    (unsigned char*)imageBase + site->leaOffsets[0],
                    patchedLeas,
                    patchedLengths);
            }
        }

        if (patchedFastBlocks > 0)
        {
            LogMessage(
                "[*] Patched %lu hardcoded MASQUE sites, falling back to dynamic scan for others",
                patchedFastBlocks);
        }
    }

    sections = IMAGE_FIRST_SECTION(ntHeaders);
    for (sectionIndex = 0; sectionIndex < ntHeaders->FileHeader.NumberOfSections; ++sectionIndex)
    {
        const IMAGE_SECTION_HEADER* section = &sections[sectionIndex];
        unsigned char* sectionBase;
        SIZE_T sectionSize;
        SIZE_T offset;

        if (!IsExecutableSection(section))
        {
            continue;
        }

        sectionBase = (unsigned char*)imageBase + section->VirtualAddress;
        sectionSize = section->Misc.VirtualSize;
        if (sectionSize < RIP_RELATIVE_LEA_SIZE)
        {
            continue;
        }

        offset = 0;
        while (offset + RIP_RELATIVE_LEA_SIZE <= sectionSize)
        {
            SIZE_T blockStartOffset = offset;
            SIZE_T blockLeaOffsets[MAX_STATIC_CODE_PATCH_BLOCK_LEAS];
            SIZE_T blockLeaCount = 0;
            SIZE_T scanOffset = offset;

            while (scanOffset + RIP_RELATIVE_LEA_SIZE <= sectionSize &&
                   scanOffset - blockStartOffset <= 0x60)
            {
                uintptr_t instructionAddress = (uintptr_t)sectionBase + scanOffset;
                uintptr_t targetAddress;

                if (TryResolveRipRelativeLeaTarget(
                        sectionBase + scanOffset,
                        instructionAddress,
                        &targetAddress) &&
                    FindKnownHostnameMatchByAddress(targetAddress, matches, matchCount))
                {
                    if (blockLeaCount < sizeof(blockLeaOffsets) / sizeof(blockLeaOffsets[0]))
                    {
                        blockLeaOffsets[blockLeaCount++] = scanOffset;
                    }
                }

                scanOffset++;
            }

            if (blockLeaCount >= 1)
            {
                SIZE_T blockStart = blockLeaOffsets[0] > STATIC_CODE_PATCH_WINDOW_BEFORE
                    ? blockLeaOffsets[0] - STATIC_CODE_PATCH_WINDOW_BEFORE
                    : 0;
                SIZE_T blockEnd = blockLeaOffsets[blockLeaCount - 1] +
                    RIP_RELATIVE_LEA_SIZE +
                    STATIC_CODE_PATCH_WINDOW_AFTER;
                SIZE_T leaIndex;
                DWORD patchedLeas = 0;
                DWORD patchedLengths;

                if (blockEnd > sectionSize)
                {
                    blockEnd = sectionSize;
                }

                for (leaIndex = 0; leaIndex < blockLeaCount; ++leaIndex)
                {
                    if (PatchRipRelativeLeaInstruction(
                            sectionBase + blockLeaOffsets[leaIndex],
                            g_pStaticReplacementSni))
                    {
                        patchedLeas++;
                    }
                }

                patchedLengths = PatchKnownLengthImmediatesInRange(
                    sectionBase + blockStart,
                    blockEnd - blockStart,
                    g_StaticReplacementSniLength);
                if (patchedLeas > 0)
                {
                    totalPatchedBlocks++;
                    totalPatchedLeas += patchedLeas;
                    totalPatchedLengths += patchedLengths;
                    LogMessage(
                        "[+] Patched static hostname code block at %p (%lu LEA references, %lu length immediates)",
                        sectionBase + blockStartOffset,
                        patchedLeas,
                        patchedLengths);
                }

                offset = blockLeaOffsets[blockLeaCount - 1] + RIP_RELATIVE_LEA_SIZE;
                continue;
            }

            offset++;
        }
    }

    if (totalPatchedBlocks > 0)
    {
        LogMessage(
            "[+] Patched %lu static hostname selection block(s) (%lu LEA references, %lu length immediates)",
            totalPatchedBlocks,
            totalPatchedLeas,
            totalPatchedLengths);
        LogMessage(
            "[*] Static MASQUE hostname selection now points to configured SNI: %s",
            replacementSni);
    }

    return totalPatchedBlocks;
}

static DWORD PatchStaticWarpHostnameReferences(void)
{
    HMODULE mainModule = GetModuleHandleA(NULL);
    const IMAGE_NT_HEADERS* ntHeaders;
    const IMAGE_SECTION_HEADER* sections;
    const unsigned char* imageBase;
    char replacementSni[MAX_PATH];
    char modulePath[MAX_PATH];
    DWORD totalPatchedCount = 0;
    DWORD patchedCodeBlocks = 0;
    DWORD knownSniIndex;
    WORD sectionIndex;

    if (!mainModule)
    {
        return 0;
    }

    if (!Config_CopySNI(replacementSni, sizeof(replacementSni)))
    {
        return 0;
    }

    if (!EnsureStaticReplacementSniBuffer(mainModule, replacementSni))
    {
        return 0;
    }

    modulePath[0] = '\0';
    GetModuleFileNameA(mainModule, modulePath, sizeof(modulePath));

    if (!GetModuleImageLayout(mainModule, &imageBase, NULL, &ntHeaders))
    {
        LogMessage("[!] Failed to inspect the main module image for static hostname patching");
        return 0;
    }

    sections = IMAGE_FIRST_SECTION(ntHeaders);
    for (knownSniIndex = 0;
         knownSniIndex < sizeof(g_KnownWARPSs) / sizeof(g_KnownWARPSs[0]);
         ++knownSniIndex)
    {
        const WARP_KNOWN_SNI* knownSni = &g_KnownWARPSs[knownSniIndex];
        const unsigned char* hostnameOccurrences[MAX_STATIC_HOSTNAME_OCCURRENCES];
        SIZE_T occurrenceCount = CollectStaticHostnameOccurrences(
            mainModule,
            knownSni->value,
            hostnameOccurrences,
            sizeof(hostnameOccurrences) / sizeof(hostnameOccurrences[0]));
        DWORD patchedCountForHostname = 0;

        if (_stricmp(replacementSni, knownSni->value) == 0)
        {
            continue;
        }

        if (occurrenceCount == 0)
        {
            continue;
        }

        for (sectionIndex = 0; sectionIndex < ntHeaders->FileHeader.NumberOfSections; ++sectionIndex)
        {
            const IMAGE_SECTION_HEADER* section = &sections[sectionIndex];
            const unsigned char* sectionBase;
            SIZE_T sectionSize;
            SIZE_T offset;

            if (!IsNonExecutableDataSection(section))
            {
                continue;
            }

            sectionBase = imageBase + section->VirtualAddress;
            sectionSize = section->Misc.VirtualSize;
            if (sectionSize < sizeof(uintptr_t) + sizeof(SIZE_T))
            {
                continue;
            }

            for (offset = 0; offset <= sectionSize - (sizeof(uintptr_t) + sizeof(SIZE_T)); ++offset)
            {
                uintptr_t referencedAddress;
                SIZE_T referencedLength;
                unsigned char* patchLocation;

                memcpy(&referencedAddress, sectionBase + offset, sizeof(referencedAddress));
                memcpy(
                    &referencedLength,
                    sectionBase + offset + sizeof(referencedAddress),
                    sizeof(referencedLength));

                if (referencedLength != knownSni->length ||
                    !MatchesStaticHostnameOccurrence(
                        referencedAddress,
                        hostnameOccurrences,
                        occurrenceCount))
                {
                    continue;
                }

                patchLocation = (unsigned char*)sectionBase + offset;
                if (!PatchRustStringReference(
                        patchLocation,
                        g_pStaticReplacementSni,
                        g_StaticReplacementSniLength))
                {
                    continue;
                }

                patchedCountForHostname++;
            }
        }

        if (patchedCountForHostname > 0)
        {
            totalPatchedCount += patchedCountForHostname;
            LogMessage(
                "[+] Patched %lu static hostname reference(s): %s -> %s",
                patchedCountForHostname,
                knownSni->value,
                replacementSni);
        }
        else
        {
            LogMessage(
                "[*] Found %s in %s but no Rust string references matched it",
                knownSni->value,
                modulePath[0] ? modulePath : "<main module>");
        }
    }

    if (totalPatchedCount > 0)
    {
        LogMessage(
            "[+] Patched %lu static WARP hostname reference(s) in %s",
            totalPatchedCount,
            modulePath[0] ? modulePath : "<main module>");
    }

    patchedCodeBlocks = PatchStaticWarpHostnameSelectionCode(mainModule, replacementSni);
    return totalPatchedCount + patchedCodeBlocks;
}

static BOOL EndsWithSuffix(const char* value, const char* suffix)
{
    size_t valueLength;
    size_t suffixLength;

    if (!value || !suffix)
    {
        return FALSE;
    }

    valueLength = strlen(value);
    suffixLength = strlen(suffix);
    if (suffixLength > valueLength)
    {
        return FALSE;
    }

    return _stricmp(value + valueLength - suffixLength, suffix) == 0;
}

static FARPROC FindExportBySuffix(
    HMODULE module,
    const char* exactName,
    const char* suffix,
    char* resolvedName,
    size_t resolvedNameLength)
{
    const unsigned char* imageBase = (const unsigned char*)module;
    const IMAGE_DOS_HEADER* dosHeader;
    const IMAGE_NT_HEADERS* ntHeaders;
    const IMAGE_EXPORT_DIRECTORY* exportDirectory;
    const DWORD* exportNames;
    const WORD* exportOrdinals;
    const DWORD* exportFunctions;
    DWORD index;

    if (!module || !exactName || !suffix)
    {
        return NULL;
    }

    dosHeader = (const IMAGE_DOS_HEADER*)imageBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }

    ntHeaders = (const IMAGE_NT_HEADERS*)(imageBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT ||
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
    {
        return NULL;
    }

    exportDirectory = (const IMAGE_EXPORT_DIRECTORY*)(
        imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    exportNames = (const DWORD*)(imageBase + exportDirectory->AddressOfNames);
    exportOrdinals = (const WORD*)(imageBase + exportDirectory->AddressOfNameOrdinals);
    exportFunctions = (const DWORD*)(imageBase + exportDirectory->AddressOfFunctions);

    for (index = 0; index < exportDirectory->NumberOfNames; ++index)
    {
        const char* exportName = (const char*)(imageBase + exportNames[index]);

        if (_stricmp(exportName, exactName) == 0 || EndsWithSuffix(exportName, suffix))
        {
            WORD ordinalIndex = exportOrdinals[index];
            DWORD functionRva;

            if (ordinalIndex >= exportDirectory->NumberOfFunctions)
            {
                continue;
            }

            functionRva = exportFunctions[ordinalIndex];
            if (resolvedName && resolvedNameLength > 0)
            {
                strncpy(resolvedName, exportName, resolvedNameLength - 1);
                resolvedName[resolvedNameLength - 1] = '\0';
            }

            return (FARPROC)(imageBase + functionRva);
        }
    }

    return NULL;
}

static BOOL InstallInlineHook(
    HOOK_SLOT* slot,
    void* pTarget,
    void* pDetour,
    void** ppOriginal)
{
    DWORD oldProtect;
    unsigned char* trampoline;

    if (!slot || !pTarget || !pDetour || !ppOriginal)
    {
        return FALSE;
    }

    memcpy(slot->originalBytes, pTarget, JUMP_SIZE);
    slot->target = (unsigned char*)pTarget;

    trampoline = (unsigned char*)VirtualAlloc(
        NULL,
        TRAMPOLINE_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!trampoline)
    {
        LogMessage("[!] VirtualAlloc for trampoline failed: %lu", GetLastError());
        return FALSE;
    }

    memcpy(trampoline, slot->originalBytes, JUMP_SIZE);
    WriteJumpInstruction(trampoline + JUMP_SIZE, slot->target + JUMP_SIZE);

    if (!VirtualProtect(pTarget, JUMP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        LogMessage("[!] VirtualProtect failed: %lu", GetLastError());
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return FALSE;
    }

    WriteJumpInstruction((unsigned char*)pTarget, pDetour);

    VirtualProtect(pTarget, JUMP_SIZE, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), pTarget, JUMP_SIZE);
    FlushInstructionCache(GetCurrentProcess(), trampoline, TRAMPOLINE_SIZE);

    slot->trampoline = trampoline;
    *ppOriginal = trampoline;
    slot->installed = TRUE;

    return TRUE;
}

static FARPROC FindTargetFunction(
    const char* exactName,
    const char* suffix,
    HMODULE* outModule,
    char* resolvedName,
    size_t resolvedNameLength)
{
    static const char* const directNames[] = {
        "aws_lc_fips_0_13_7_crypto_original.dll",
        "aws_lc_fips_0_13_7_crypto.dll",
        "aws_lc_fips_crypto.dll",
        "libssl.dll",
        "libcrypto.dll",
        NULL
    };
    HMODULE hModule;
    HMODULE modules[1024];
    DWORD bytesNeeded;
    DWORD index;

    if (!exactName || !suffix)
    {
        return NULL;
    }

    for (index = 0; directNames[index] != NULL; ++index)
    {
        hModule = GetModuleHandleA(directNames[index]);
        if (hModule)
        {
            FARPROC target = FindExportBySuffix(
                hModule,
                exactName,
                suffix,
                resolvedName,
                resolvedNameLength);

            if (target)
            {
                if (outModule)
                {
                    *outModule = hModule;
                }

                return target;
            }
        }
    }

    if (!WARPSEnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &bytesNeeded))
    {
        return NULL;
    }

    for (index = 0; index < bytesNeeded / sizeof(HMODULE); ++index)
    {
        char modulePath[MAX_PATH];

        if (!WARPSGetModuleFileNameExA(
                GetCurrentProcess(),
                modules[index],
                modulePath,
                sizeof(modulePath)))
        {
            continue;
        }

        if (strstr(modulePath, "aws_lc") ||
            strstr(modulePath, "crypto") ||
            strstr(modulePath, "ssl"))
        {
            FARPROC target = FindExportBySuffix(
                modules[index],
                exactName,
                suffix,
                resolvedName,
                resolvedNameLength);

            if (target)
            {
                if (outModule)
                {
                    *outModule = modules[index];
                }

                return target;
            }
        }
    }

    return NULL;
}

static BOOL TryLocateSNIExtensionEx(
    const unsigned char* clientHello,
    SIZE_T availableHelloLen,
    SIZE_T declaredHelloLen,
    TLS_SNI_LOCATION* location,
    BOOL allowTruncated)
{
    SIZE_T offset = TLS_CLIENT_HELLO_FIXED_SIZE;
    SIZE_T extensionsLengthOffset;
    SIZE_T declaredExtensionsEnd;
    SIZE_T parseLimit;

    if (!clientHello ||
        !location ||
        availableHelloLen < TLS_CLIENT_HELLO_FIXED_SIZE ||
        declaredHelloLen < TLS_CLIENT_HELLO_FIXED_SIZE)
    {
        return FALSE;
    }

    memset(location, 0, sizeof(*location));

    if (!HasRange(offset, 1, availableHelloLen))
    {
        return FALSE;
    }
    offset += 1 + clientHello[offset];

    if (!HasRange(offset, 2, availableHelloLen))
    {
        return FALSE;
    }
    offset += 2 + ReadUInt16BE(clientHello + offset);

    if (!HasRange(offset, 1, availableHelloLen))
    {
        return FALSE;
    }
    offset += 1 + clientHello[offset];

    if (!HasRange(offset, 2, availableHelloLen))
    {
        return FALSE;
    }

    extensionsLengthOffset = offset;
    location->extensionsLength = ReadUInt16BE(clientHello + offset);
    declaredExtensionsEnd = offset + 2 + location->extensionsLength;
    if (declaredExtensionsEnd > declaredHelloLen)
    {
        return FALSE;
    }

    parseLimit = declaredExtensionsEnd;
    if (allowTruncated && parseLimit > availableHelloLen)
    {
        parseLimit = availableHelloLen;
    }
    else if (!allowTruncated && parseLimit > availableHelloLen)
    {
        return FALSE;
    }

    offset += 2;

    while (HasRange(offset, 4, parseLimit))
    {
        WORD extensionType = ReadUInt16BE(clientHello + offset);
        WORD extensionLength = ReadUInt16BE(clientHello + offset + 2);
        SIZE_T extensionDataOffset = offset + 4;
        SIZE_T declaredExtensionEnd = extensionDataOffset + extensionLength;

        if (!HasRange(extensionDataOffset, extensionLength, declaredExtensionsEnd))
        {
            return FALSE;
        }

        if (!HasRange(extensionDataOffset, extensionLength, parseLimit))
        {
            return FALSE;
        }

        if (extensionType == TLS_EXTENSION_TYPE_SERVER_NAME)
        {
            WORD serverNameListLength;
            SIZE_T nameLengthOffset;
            WORD serverNameLength;
            SIZE_T serverNameOffset;

            if (extensionLength < 5)
            {
                return FALSE;
            }

            serverNameListLength = ReadUInt16BE(clientHello + extensionDataOffset);
            if ((SIZE_T)serverNameListLength + 2 > extensionLength)
            {
                return FALSE;
            }

            if (clientHello[extensionDataOffset + 2] != TLS_SNI_NAME_TYPE_HOST_NAME)
            {
                return FALSE;
            }

            nameLengthOffset = extensionDataOffset + 3;
            if (!HasRange(nameLengthOffset, 2, parseLimit))
            {
                return FALSE;
            }

            serverNameLength = ReadUInt16BE(clientHello + nameLengthOffset);
            if ((SIZE_T)serverNameLength + 3 > serverNameListLength)
            {
                return FALSE;
            }

            serverNameOffset = nameLengthOffset + 2;
            if (!HasRange(serverNameOffset, serverNameLength, availableHelloLen))
            {
                return FALSE;
            }

            location->extensionsLengthOffset = extensionsLengthOffset;
            location->extensionLengthOffset = offset + 2;
            location->serverNameListLengthOffset = extensionDataOffset;
            location->serverNameLengthOffset = nameLengthOffset;
            location->serverNameOffset = serverNameOffset;
            location->extensionLength = extensionLength;
            location->serverNameListLength = serverNameListLength;
            location->serverNameLength = serverNameLength;
            return TRUE;
        }

        offset = declaredExtensionEnd;
    }

    return FALSE;
}

static BOOL TryLocateSNIExtension(
    const unsigned char* clientHello,
    SIZE_T helloLen,
    TLS_SNI_LOCATION* location)
{
    return TryLocateSNIExtensionEx(
        clientHello,
        helloLen,
        helloLen,
        location,
        FALSE);
}

static BOOL TryCopySniFromClientHelloBody(
    const unsigned char* clientHello,
    SIZE_T helloLen,
    char* sni,
    size_t sniCapacity)
{
    TLS_SNI_LOCATION location;

    if (!TryLocateSNIExtension(clientHello, helloLen, &location))
    {
        return FALSE;
    }

    return TryCopySniBytes(
        clientHello + location.serverNameOffset,
        location.serverNameLength,
        sni,
        sniCapacity);
}

BOOL IsClientHelloBuffer(const unsigned char* data, SIZE_T len)
{
    const unsigned char* handshake;
    SIZE_T handshakeBytes;
    WORD recordLength;
    DWORD clientHelloLength;

    if (!data || len < TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE)
    {
        return FALSE;
    }

    if (data[0] != TLS_RECORD_TYPE_HANDSHAKE)
    {
        return FALSE;
    }

    recordLength = ReadUInt16BE(data + 3);
    if (recordLength > len - TLS_RECORD_HEADER_SIZE)
    {
        return FALSE;
    }

    handshake = data + TLS_RECORD_HEADER_SIZE;
    handshakeBytes = len - TLS_RECORD_HEADER_SIZE;

    if (handshake[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
    {
        return FALSE;
    }

    clientHelloLength = ReadUInt24BE(handshake + 1);
    if ((SIZE_T)clientHelloLength < TLS_CLIENT_HELLO_FIXED_SIZE)
    {
        return FALSE;
    }

    if ((SIZE_T)clientHelloLength > handshakeBytes - TLS_HANDSHAKE_HEADER_SIZE)
    {
        return FALSE;
    }

    return TRUE;
}

BOOL IsHandshakeClientHello(const unsigned char* data, SIZE_T len)
{
    DWORD handshakeLength;

    if (!data || len < TLS_HANDSHAKE_HEADER_SIZE + TLS_CLIENT_HELLO_FIXED_SIZE)
    {
        return FALSE;
    }

    if (data[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
    {
        return FALSE;
    }

    handshakeLength = ReadUInt24BE(data + 1);
    if ((SIZE_T)handshakeLength < TLS_CLIENT_HELLO_FIXED_SIZE)
    {
        return FALSE;
    }

    if ((SIZE_T)handshakeLength > len - TLS_HANDSHAKE_HEADER_SIZE)
    {
        return FALSE;
    }

    return TRUE;
}

static BOOL TryGetRawClientHelloInfo(
    const unsigned char* data,
    SIZE_T len,
    const unsigned char** clientHello,
    SIZE_T* availableClientHelloLength,
    SIZE_T* declaredClientHelloLength,
    BOOL* truncated)
{
    DWORD handshakeLength;
    SIZE_T availableLength;

    if (!data || len < TLS_HANDSHAKE_HEADER_SIZE + TLS_CLIENT_HELLO_FIXED_SIZE)
    {
        return FALSE;
    }

    if (data[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
    {
        return FALSE;
    }

    handshakeLength = ReadUInt24BE(data + 1);
    if ((SIZE_T)handshakeLength < TLS_CLIENT_HELLO_FIXED_SIZE)
    {
        return FALSE;
    }

    availableLength = len - TLS_HANDSHAKE_HEADER_SIZE;
    if ((SIZE_T)handshakeLength < availableLength)
    {
        availableLength = (SIZE_T)handshakeLength;
    }

    if (clientHello)
    {
        *clientHello = data + TLS_HANDSHAKE_HEADER_SIZE;
    }

    if (availableClientHelloLength)
    {
        *availableClientHelloLength = availableLength;
    }

    if (declaredClientHelloLength)
    {
        *declaredClientHelloLength = (SIZE_T)handshakeLength;
    }

    if (truncated)
    {
        *truncated = availableLength < (SIZE_T)handshakeLength;
    }

    return TRUE;
}

static BOOL TryExtractSniFromClientHelloHandshake(
    const unsigned char* data,
    SIZE_T len,
    char* sni,
    size_t sniCapacity)
{
    const unsigned char* clientHello;
    SIZE_T availableClientHelloLength;
    SIZE_T declaredClientHelloLength;
    BOOL truncated;

    if (!TryGetRawClientHelloInfo(
            data,
            len,
            &clientHello,
            &availableClientHelloLength,
            &declaredClientHelloLength,
            &truncated) ||
        truncated)
    {
        return FALSE;
    }

    return TryCopySniFromClientHelloBody(
        clientHello,
        declaredClientHelloLength,
        sni,
        sniCapacity);
}

static BOOL TryExtractSniFromClientHelloHandshakePrefix(
    const unsigned char* data,
    SIZE_T len,
    char* sni,
    size_t sniCapacity)
{
    const unsigned char* clientHello;
    SIZE_T availableClientHelloLength;
    SIZE_T declaredClientHelloLength;
    TLS_SNI_LOCATION location;
    BOOL truncated;

    if (!TryGetRawClientHelloInfo(
            data,
            len,
            &clientHello,
            &availableClientHelloLength,
            &declaredClientHelloLength,
            &truncated) ||
        !truncated)
    {
        return FALSE;
    }

    if (!TryLocateSNIExtensionEx(
            clientHello,
            availableClientHelloLength,
            declaredClientHelloLength,
            &location,
            TRUE))
    {
        return FALSE;
    }

    return TryCopySniBytes(
        clientHello + location.serverNameOffset,
        location.serverNameLength,
        sni,
        sniCapacity);
}

static BOOL TryExtractSniFromTlsRecord(
    const unsigned char* data,
    SIZE_T len,
    char* sni,
    size_t sniCapacity)
{
    DWORD clientHelloLength;
    const unsigned char* handshake;
    const unsigned char* clientHello;

    if (!IsClientHelloBuffer(data, len))
    {
        return FALSE;
    }

    handshake = data + TLS_RECORD_HEADER_SIZE;
    clientHelloLength = ReadUInt24BE(handshake + 1);
    clientHello = handshake + TLS_HANDSHAKE_HEADER_SIZE;

    return TryCopySniFromClientHelloBody(
        clientHello,
        clientHelloLength,
        sni,
        sniCapacity);
}

BOOL TryExtractObservedSni(
    const unsigned char* data,
    SIZE_T len,
    char* sni,
    size_t sniCapacity,
    const char** sourceKind)
{
    if (TryExtractSniFromTlsRecord(data, len, sni, sniCapacity))
    {
        if (sourceKind)
        {
            *sourceKind = "tls-record";
        }

        return TRUE;
    }

    if (TryExtractSniFromClientHelloHandshake(data, len, sni, sniCapacity))
    {
        if (sourceKind)
        {
            *sourceKind = "handshake";
        }

        return TRUE;
    }

    if (TryExtractSniFromClientHelloHandshakePrefix(data, len, sni, sniCapacity))
    {
        if (sourceKind)
        {
            *sourceKind = "handshake-prefix";
        }

        return TRUE;
    }

    return FALSE;
}

static BOOL LogObservedSni(
    const char* hookLabel,
    const unsigned char* data,
    SIZE_T len)
{
    char sni[MAX_PATH];
    const char* sourceKind = "unknown";

    if (!hookLabel || !data)
    {
        return FALSE;
    }

    if (!TryExtractObservedSni(data, len, sni, sizeof(sni), &sourceKind))
    {
        return FALSE;
    }

    LogMessage(
        "[*] %s observed SNI (%s): %s",
        hookLabel,
        sourceKind,
        sni);

    return TRUE;
}

SIZE_T FindSNIExtension(const unsigned char* clientHello, SIZE_T helloLen, WORD* outExtensionLen)
{
    TLS_SNI_LOCATION location;

    if (!TryLocateSNIExtension(clientHello, helloLen, &location))
    {
        if (outExtensionLen)
        {
            *outExtensionLen = 0;
        }

        return 0;
    }

    if (outExtensionLen)
    {
        *outExtensionLen = location.extensionLength;
    }

    return location.serverNameLengthOffset;
}

static BOOL IsKnownWARPS(const char* sni, size_t sniLen)
{
    size_t index;

    for (index = 0; index < sizeof(g_KnownWARPSs) / sizeof(g_KnownWARPSs[0]); ++index)
    {
        if (sniLen == g_KnownWARPSs[index].length &&
            memcmp(sni, g_KnownWARPSs[index].value, sniLen) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static const WARP_KNOWN_SNI* FindMatchingWARPS(
    const unsigned char* data,
    size_t dataLen)
{
    size_t index;

    if (!data)
    {
        return NULL;
    }

    for (index = 0; index < sizeof(g_KnownWARPSs) / sizeof(g_KnownWARPSs[0]); ++index)
    {
        if (dataLen == g_KnownWARPSs[index].length &&
            memcmp(data, g_KnownWARPSs[index].value, dataLen) == 0)
        {
            return &g_KnownWARPSs[index];
        }
    }

    return NULL;
}

static unsigned char* CreateModifiedClientHelloCopy(
    const unsigned char* data,
    SIZE_T len,
    SIZE_T* newLen,
    const char* newSNI)
{
    unsigned char* copiedData;
    unsigned char* modifiedData;

    if (!data || !newLen || !newSNI)
    {
        return NULL;
    }

    copiedData = (unsigned char*)malloc(len);
    if (!copiedData)
    {
        LogMessage("[!] Failed to allocate temporary ClientHello copy");
        return NULL;
    }

    memcpy(copiedData, data, len);
    *newLen = len;

    modifiedData = ModifyClientHelloSNI(copiedData, newLen, newSNI);
    if (modifiedData != copiedData)
    {
        free(copiedData);
    }

    return modifiedData;
}

static void* ForwardModifiedCryptoBufferCall(
    const char* hookLabel,
    volatile LONG* hitCounter,
    CRYPTO_BUFFER_new_TYPE originalFn,
    const unsigned char* data,
    size_t len,
    void* pool)
{
    LONG hitCount = RegisterHookHit(hitCounter);
    unsigned char* modifiedData = NULL;
    SIZE_T mutableLen = (SIZE_T)len;
    char sni[MAX_PATH];
    void* result;
    BOOL isTlsRecord = data && IsClientHelloBuffer(data, len);
    BOOL isRawHandshake = data && !isTlsRecord && IsHandshakeClientHello(data, len);

    if (data && len > 0 && !isTlsRecord && !isRawHandshake)
    {
        if (!LogObservedSni(hookLabel, data, len))
        {
            LogHookHitSample(hookLabel, hitCount, data, len);
        }
    }

    if (isTlsRecord || isRawHandshake)
    {
        LogMessage("[*] %s: Detected ClientHello (%s, %u bytes)", 
            hookLabel, 
            isTlsRecord ? "record-wrapped" : "raw-handshake",
            (unsigned int)len);

        if (!LogObservedSni(hookLabel, data, len))
        {
            LogMessage("[*] %s: ClientHello did not contain a parsable SNI extension", hookLabel);
        }

        if (Config_CopySNI(sni, sizeof(sni)))
        {
            modifiedData = CreateModifiedClientHelloCopy(data, mutableLen, &mutableLen, sni);
        }
    }

    if (!originalFn)
    {
        if (modifiedData)
        {
            free(modifiedData);
        }
        return NULL;
    }

    result = originalFn(
        modifiedData ? modifiedData : data,
        modifiedData ? mutableLen : len,
        pool);

    if (modifiedData)
    {
        free(modifiedData);
    }

    return result;
}

static unsigned char* RebuildClientHelloSNI(
    const unsigned char* data,
    SIZE_T* len,
    const char* newSNI,
    const TLS_SNI_LOCATION* location,
    BOOL isRawHandshake)
{
    unsigned char* rebuiltData;
    SIZE_T totalLen;
    SIZE_T newTotalLen;
    SIZE_T prefixLen;
    SIZE_T oldSuffixOffset;
    size_t newSniLen;
    SSIZE_T delta;
    SIZE_T recordLength = 0;
    SIZE_T handshakeLength;
    SIZE_T newRecordLength = 0;
    SIZE_T newHandshakeLength;
    SIZE_T newExtensionsLength;
    SIZE_T newExtensionLength;
    SIZE_T newServerNameListLength;
    unsigned char* rebuiltHandshake;
    unsigned char* rebuiltClientHello;
    SIZE_T headerSize = isRawHandshake ? TLS_HANDSHAKE_HEADER_SIZE : (TLS_RECORD_HEADER_SIZE + TLS_HANDSHAKE_HEADER_SIZE);

    if (!data || !len || !newSNI || !location)
    {
        return (unsigned char*)data;
    }

    totalLen = *len;
    newSniLen = strlen(newSNI);
    delta = (SSIZE_T)newSniLen - (SSIZE_T)location->serverNameLength;

    if (!TryApplyDeltaToSize(totalLen, delta, &newTotalLen))
    {
        LogMessage("[!] Failed to resize ClientHello buffer");
        return (unsigned char*)data;
    }

    prefixLen = headerSize + location->serverNameOffset;
    oldSuffixOffset = prefixLen + location->serverNameLength;
    if (prefixLen > totalLen || oldSuffixOffset > totalLen)
    {
        LogMessage("[!] SNI offsets are outside the TLS buffer");
        return (unsigned char*)data;
    }

    if (!isRawHandshake)
    {
        recordLength = ReadUInt16BE(data + 3);
        if (!TryApplyDeltaToSize(recordLength, delta, &newRecordLength) || newRecordLength > 0xFFFF)
        {
            LogMessage("[!] TLS record length cannot represent the rebuilt SNI");
            return (unsigned char*)data;
        }
    }

    handshakeLength = ReadUInt24BE(data + (isRawHandshake ? 1 : (TLS_RECORD_HEADER_SIZE + 1)));
    if (!TryApplyDeltaToSize(handshakeLength, delta, &newHandshakeLength) ||
        !TryApplyDeltaToSize(location->extensionsLength, delta, &newExtensionsLength) ||
        !TryApplyDeltaToSize(location->extensionLength, delta, &newExtensionLength) ||
        !TryApplyDeltaToSize(location->serverNameListLength, delta, &newServerNameListLength) ||
        newHandshakeLength > 0xFFFFFF ||
        newExtensionsLength > 0xFFFF ||
        newExtensionLength > 0xFFFF ||
        newServerNameListLength > 0xFFFF)
    {
        LogMessage("[!] TLS length fields cannot represent the rebuilt SNI");
        return (unsigned char*)data;
    }

    rebuiltData = (unsigned char*)malloc(newTotalLen);
    if (!rebuiltData)
    {
        LogMessage("[!] Failed to allocate rebuilt ClientHello buffer");
        return (unsigned char*)data;
    }

    memcpy(rebuiltData, data, prefixLen);
    memcpy(rebuiltData + prefixLen, newSNI, newSniLen);
    memcpy(
        rebuiltData + prefixLen + newSniLen,
        data + oldSuffixOffset,
        totalLen - oldSuffixOffset);

    rebuiltHandshake = rebuiltData + (isRawHandshake ? 0 : TLS_RECORD_HEADER_SIZE);
    rebuiltClientHello = rebuiltHandshake + TLS_HANDSHAKE_HEADER_SIZE;

    if (!isRawHandshake)
    {
        WriteUInt16BE(rebuiltData + 3, (WORD)newRecordLength);
    }
    WriteUInt24BE(rebuiltHandshake + 1, (DWORD)newHandshakeLength);
    WriteUInt16BE(
        rebuiltClientHello + location->extensionsLengthOffset,
        (WORD)newExtensionsLength);
    WriteUInt16BE(
        rebuiltClientHello + location->extensionLengthOffset,
        (WORD)newExtensionLength);
    WriteUInt16BE(
        rebuiltClientHello + location->serverNameListLengthOffset,
        (WORD)newServerNameListLength);
    WriteUInt16BE(
        rebuiltClientHello + location->serverNameLengthOffset,
        (WORD)newSniLen);

    *len = newTotalLen;
    LogMessage("[+] SNI replaced with rebuilt ClientHello (%s): %s", 
        isRawHandshake ? "raw" : "record", newSNI);
    return rebuiltData;
}

unsigned char* ModifyClientHelloSNI(unsigned char* data, SIZE_T* len, const char* newSNI)
{
    const unsigned char* handshake;
    const unsigned char* clientHello;
    SIZE_T clientHelloLen;
    SIZE_T availableClientHelloLen = 0;
    SIZE_T declaredClientHelloLen = 0;
    TLS_SNI_LOCATION location;
    char oldSni[MAX_PATH];
    BOOL haveOldSni = FALSE;
    size_t newSniLen;
    BOOL isTlsRecord = IsClientHelloBuffer(data, *len);
    BOOL isRawHandshake = !isTlsRecord && IsHandshakeClientHello(data, *len);
    BOOL isRawHandshakePrefix = FALSE;
    const char* formatKind = "raw";

    if (!data || !len || !newSNI)
    {
        return data;
    }

    if (!isTlsRecord && !isRawHandshake)
    {
        if (!TryGetRawClientHelloInfo(
                data,
                *len,
                &clientHello,
                &availableClientHelloLen,
                &declaredClientHelloLen,
                &isRawHandshakePrefix) ||
            !isRawHandshakePrefix)
        {
            return data;
        }

        handshake = data;
        clientHelloLen = availableClientHelloLen;
        formatKind = "raw-prefix";
    }
    else
    {
        handshake = data + (isRawHandshake ? 0 : TLS_RECORD_HEADER_SIZE);
        clientHello = handshake + TLS_HANDSHAKE_HEADER_SIZE;
        clientHelloLen = ReadUInt24BE(handshake + 1);
        availableClientHelloLen = clientHelloLen;
        declaredClientHelloLen = clientHelloLen;
        formatKind = isTlsRecord ? "record" : "raw";
    }

    if (!TryLocateSNIExtensionEx(
            clientHello,
            availableClientHelloLen,
            declaredClientHelloLen,
            &location,
            isRawHandshakePrefix))
    {
        if (isRawHandshakePrefix)
        {
            LogMessage(
                "[!] Could not find SNI extension in ClientHello (%s, %u/%u bytes available)",
                formatKind,
                (unsigned int)availableClientHelloLen,
                (unsigned int)declaredClientHelloLen);
        }
        else
        {
            LogMessage("[!] Could not find SNI extension in ClientHello (%s)", formatKind);
        }
        return data;
    }

    haveOldSni = TryCopySniBytes(
        clientHello + location.serverNameOffset,
        location.serverNameLength,
        oldSni,
        sizeof(oldSni));

    if (haveOldSni && _stricmp(oldSni, newSNI) == 0)
    {
        LogMessage(
            "[*] ClientHello already uses configured SNI (%s): %s",
            formatKind,
            oldSni);
        return data;
    }

    if (!IsKnownWARPS(
            (const char*)clientHello + location.serverNameOffset,
            location.serverNameLength))
    {
        if (haveOldSni)
        {
            LogMessage("[*] SNI '%s' is not a recognized WARP MASQUE hostname, skipping modification", oldSni);
        }
        else
        {
            LogMessage("[*] unrecognized SNI extension, skipping modification");
        }
        return data;
    }

    newSniLen = strlen(newSNI);
    if (isRawHandshakePrefix && newSniLen != location.serverNameLength)
    {
        LogMessage(
            "[!] ClientHello prefix contains SNI '%s' but only %u/%u bytes are available; cannot perform length-changing rewrite to '%s'",
            haveOldSni ? oldSni : "<unavailable>",
            (unsigned int)availableClientHelloLen,
            (unsigned int)declaredClientHelloLen,
            newSNI);
        return data;
    }

    if (newSniLen == location.serverNameLength)
    {
        memcpy(
            (unsigned char*)clientHello + location.serverNameOffset,
            newSNI,
            newSniLen);
        LogMessage("[+] SNI replaced in-place (%s): %s", formatKind, newSNI);
        return data;
    }

    return RebuildClientHelloSNI(data, len, newSNI, &location, isRawHandshake);
}

static void* __cdecl Hooked_CRYPTO_BUFFER_new(const unsigned char* data, size_t len, void* pool)
{
    return ForwardModifiedCryptoBufferCall(
        "CRYPTO_BUFFER_new",
        &g_CryptoBufferNewHitCount,
        g_pfnOriginalCryptoBufferNew,
        data,
        len,
        pool);
}

static void* __cdecl Hooked_CRYPTO_BUFFER_new_from_static_data_unsafe(
    const unsigned char* data,
    size_t len,
    void* pool)
{
    return ForwardModifiedCryptoBufferCall(
        "CRYPTO_BUFFER_new_from_static_data_unsafe",
        &g_CryptoBufferNewFromStaticDataUnsafeHitCount,
        g_pfnOriginalCryptoBufferNewFromStaticDataUnsafe,
        data,
        len,
        pool);
}

static void* __cdecl Hooked_CRYPTO_BUFFER_new_from_CBS(
    const CBS* cbs,
    void* pool)
{
    LONG hitCount = RegisterHookHit(&g_CryptoBufferNewFromCbsHitCount);
    const CBS* cbsToUse = cbs;
    CBS modifiedCbs;
    unsigned char* modifiedData = NULL;
    SIZE_T mutableLen = 0;
    char sni[MAX_PATH];
    BOOL isTlsRecord = cbs && cbs->data && IsClientHelloBuffer(cbs->data, cbs->len);
    BOOL isRawHandshake = cbs && cbs->data && !isTlsRecord && IsHandshakeClientHello(cbs->data, cbs->len);

    if (cbs && cbs->data && cbs->len > 0 && !isTlsRecord && !isRawHandshake)
    {
        if (!LogObservedSni("CRYPTO_BUFFER_new_from_CBS", cbs->data, cbs->len))
        {
            LogHookHitSample("CRYPTO_BUFFER_new_from_CBS", hitCount, cbs->data, cbs->len);
        }
    }

    if (isTlsRecord || isRawHandshake)
    {
        LogMessage(
            "[*] CRYPTO_BUFFER_new_from_CBS: Detected ClientHello (%s, %u bytes)",
            isTlsRecord ? "record-wrapped" : "raw-handshake",
            (unsigned int)cbs->len);
        if (!LogObservedSni("CRYPTO_BUFFER_new_from_CBS", cbs->data, cbs->len))
        {
            LogMessage("[*] CRYPTO_BUFFER_new_from_CBS: ClientHello did not contain a parsable SNI extension");
        }

        if (Config_CopySNI(sni, sizeof(sni)))
        {
            modifiedData = CreateModifiedClientHelloCopy(cbs->data, cbs->len, &mutableLen, sni);
            if (modifiedData)
            {
                modifiedCbs.data = modifiedData;
                modifiedCbs.len = mutableLen;
                cbsToUse = &modifiedCbs;
            }
        }
    }

    if (!g_pfnOriginalCryptoBufferNewFromCbs)
    {
        if (modifiedData)
        {
            free(modifiedData);
        }
        return NULL;
    }

    {
        void* result = g_pfnOriginalCryptoBufferNewFromCbs(cbsToUse, pool);

        if (modifiedData)
        {
            free(modifiedData);
        }

        return result;
    }
}

static int __cdecl Hooked_CBB_add_bytes(
    CBB* cbb,
    const unsigned char* data,
    size_t len)
{
    LONG hitCount = RegisterHookHit(&g_CbbAddBytesHitCount);
    const WARP_KNOWN_SNI* matchedSni = FindMatchingWARPS(data, len);
    char sni[MAX_PATH];

    if (!Config_CopySNI(sni, sizeof(sni)))
    {
        if (g_pfnOriginalCbbAddBytes)
        {
            return g_pfnOriginalCbbAddBytes(cbb, data, len);
        }

        return 0;
    }

    if (matchedSni)
    {
        LogMessage(
            "[+] CBB_add_bytes matched WARP SNI bytes: %.*s -> %s",
            (int)len,
            data,
            sni);

        if (g_pfnOriginalCbbAddBytes)
        {
            return g_pfnOriginalCbbAddBytes(
                cbb,
                (const unsigned char*)sni,
                strlen(sni));
        }

        return 0;
    }

    if (data &&
        sni[0] != '\0' &&
        len == strlen(sni) &&
        memcmp(data, sni, len) == 0)
    {
        if (ShouldLogHookSample(hitCount))
        {
            LogMessage(
                "[+] CBB_add_bytes observed configured SNI bytes already active: %s",
                sni);
        }

        if (g_pfnOriginalCbbAddBytes)
        {
            return g_pfnOriginalCbbAddBytes(cbb, data, len);
        }

        return 0;
    }

    if (data && len > 0)
    {
        LogHookHitSample("CBB_add_bytes", hitCount, data, len);
    }

    if (g_pfnOriginalCbbAddBytes)
    {
        return g_pfnOriginalCbbAddBytes(cbb, data, len);
    }

    return 0;
}

static int __cdecl Hooked_CBB_finish(
    CBB* cbb,
    unsigned char** out_data,
    size_t* out_len)
{
    LONG hitCount = RegisterHookHit(&g_CbbFinishHitCount);
    int result;

    if (!g_pfnOriginalCbbFinish)
    {
        return 0;
    }

    result = g_pfnOriginalCbbFinish(cbb, out_data, out_len);
    if (result && out_data && out_len && *out_data && *out_len > 0)
    {
        if (!LogObservedSni("CBB_finish", *out_data, *out_len))
        {
            LogHookHitSample("CBB_finish", hitCount, *out_data, *out_len);
        }
    }

    return result;
}

BOOL Hooks_InitCryptoBufferNew(void)
{
    DWORD attempt;
    DWORD candidateIndex;
    char modulePath[MAX_PATH];
    DWORD installedCount = 0;

    g_hTargetModule = NULL;
    modulePath[0] = '\0';
    g_InstalledHookCount = 0;
    g_pfnOriginalCryptoBufferNew = NULL;
    g_pfnOriginalCryptoBufferNewFromStaticDataUnsafe = NULL;
    g_pfnOriginalCryptoBufferNewFromCbs = NULL;
    g_pfnOriginalCbbAddBytes = NULL;
    g_pfnOriginalCbbFinish = NULL;
    g_CryptoBufferNewHitCount = 0;
    g_CryptoBufferNewFromCbsHitCount = 0;
    g_CryptoBufferNewFromStaticDataUnsafeHitCount = 0;
    g_CbbAddBytesHitCount = 0;
    g_CbbFinishHitCount = 0;

    for (candidateIndex = 0;
         candidateIndex < sizeof(g_HookSlots) / sizeof(g_HookSlots[0]);
         ++candidateIndex)
    {
        g_HookSlots[candidateIndex].config = &g_HookCandidateConfigs[candidateIndex];
        ResetHookSlot(&g_HookSlots[candidateIndex]);
        g_HookSlots[candidateIndex].config = &g_HookCandidateConfigs[candidateIndex];
    }

    for (attempt = 0; attempt < HOOK_INIT_RETRY_COUNT; ++attempt)
    {
        HMODULE discoveredModule = NULL;
        FARPROC discoveredExport = FindTargetFunction(
            g_HookCandidateConfigs[0].exactName,
            g_HookCandidateConfigs[0].suffix,
            &discoveredModule,
            NULL,
            0);

        if (discoveredExport && discoveredModule)
        {
            g_hTargetModule = discoveredModule;
            break;
        }

        Sleep(HOOK_INIT_RETRY_DELAY_MS);
    }

    if (g_hTargetModule)
    {
        if (WARPSGetModuleFileNameExA(
                GetCurrentProcess(),
                g_hTargetModule,
                modulePath,
                sizeof(modulePath)))
        {
            LogMessage("[+] Found target crypto module: %s", modulePath);
        }

        for (candidateIndex = 0;
             candidateIndex < sizeof(g_HookSlots) / sizeof(g_HookSlots[0]);
             ++candidateIndex)
        {
            HOOK_SLOT* slot = &g_HookSlots[candidateIndex];
#if !WARPS_ENABLE_AWSLC_CBB_HOOKS
            if (slot->config == &g_HookCandidateConfigs[3] ||
                slot->config == &g_HookCandidateConfigs[4])
            {
                LogMessage(
                    "[*] Skipping broad AWS-LC builder hook candidate in precise TLS mode: %s",
                    slot->config->label);
                continue;
            }
#endif
            FARPROC targetFunction = FindExportBySuffix(
                g_hTargetModule,
                slot->config->exactName,
                slot->config->suffix,
                slot->resolvedName,
                sizeof(slot->resolvedName));

            if (!targetFunction)
            {
                LogMessage(
                    "[*] Hook candidate not exported by this AWS-LC build: %s",
                    slot->config->label);
                continue;
            }

            slot->module = g_hTargetModule;
            if (!InstallInlineHook(
                    slot,
                    targetFunction,
                    slot->config->detour,
                    slot->config->originalStorage))
            {
                LogMessage(
                    "[!] Failed to install hook candidate %s (%s)",
                    slot->config->label,
                    slot->resolvedName);
                continue;
            }

            installedCount++;
            LogMessage(
                "[+] Installed hook candidate %s via %s at %p",
                slot->config->label,
                slot->resolvedName,
                targetFunction);
        }
    }

    if (!g_hTargetModule)
    {
        LogMessage("[!] No loaded crypto module was found for AWS-LC hook installation");
        return FALSE;
    }

    g_InstalledHookCount = installedCount;
    if (installedCount == 0)
    {
        LogMessage("[!] No AWS-LC hook candidates could be installed");
        return FALSE;
    }

    LogMessage("[+] Installed %lu hook candidate(s)", installedCount);
    return TRUE;
}

BOOL Hooks_InitStaticHostnamePatches(void)
{
    if (g_StaticHostnamePatchCount > 0)
    {
        return TRUE;
    }

    g_StaticHostnamePatchCount = PatchStaticWarpHostnameReferences();
    return g_StaticHostnamePatchCount > 0;
}

BOOL Hooks_AreStaticHostnamePatchesActive(void)
{
    return g_StaticHostnamePatchCount > 0;
}


void Hooks_InitSslSetSni(void)
{
    
}

void Hooks_Cleanup(void)
{
    DWORD candidateIndex;

    for (candidateIndex = 0;
         candidateIndex < sizeof(g_HookSlots) / sizeof(g_HookSlots[0]);
         ++candidateIndex)
    {
        HOOK_SLOT* slot = &g_HookSlots[candidateIndex];

        if (slot->installed && slot->target)
        {
            DWORD oldProtect;

            VirtualProtect(slot->target, JUMP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(slot->target, slot->originalBytes, JUMP_SIZE);
            VirtualProtect(slot->target, JUMP_SIZE, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), slot->target, JUMP_SIZE);

            slot->installed = FALSE;
            LogMessage(
                "[*] Hook removed: %s",
                slot->config ? slot->config->label : "unknown");
        }

        if (slot->trampoline)
        {
            VirtualFree(slot->trampoline, 0, MEM_RELEASE);
            slot->trampoline = NULL;
        }

        if (slot->config && slot->config->originalStorage)
        {
            *slot->config->originalStorage = NULL;
        }

        ResetHookSlot(slot);
        slot->config = &g_HookCandidateConfigs[candidateIndex];
    }

    g_hTargetModule = NULL;
    g_InstalledHookCount = 0;
    if (g_StaticHostnamePatchCount == 0)
    {
        ReleaseStaticReplacementSniBuffer();
    }
    else
    {
        LogMessage("[*] Retaining static hostname patch buffer until process exit");
    }
}

BOOL Hooks_UpdateStaticSNI(const char* newSni)
{
    DWORD i;
    
    if (!newSni || !newSni[0])
    {
        return FALSE;
    }

    if (!EnsureStaticReplacementSniBuffer(GetModuleHandleA(NULL), newSni))
    {
        LogMessage("[!] Failed to allocate new static SNI buffer for runtime update");
        return FALSE;
    }

    for (i = 0; i < g_PatchedStringRefCount; ++i)
    {
        uintptr_t replacementAddress = (uintptr_t)g_pStaticReplacementSni;
        SIZE_T replacementLength = g_StaticReplacementSniLength;
        unsigned char* referenceLocation = (unsigned char*)g_PatchedStringRefs[i];
        DWORD oldProtect;

        if (VirtualProtect(
                referenceLocation,
                sizeof(replacementAddress) + sizeof(replacementLength),
                PAGE_READWRITE,
                &oldProtect))
        {
            memcpy(referenceLocation, &replacementAddress, sizeof(replacementAddress));
            memcpy(referenceLocation + sizeof(replacementAddress), &replacementLength, sizeof(replacementLength));
            VirtualProtect(
                referenceLocation,
                sizeof(replacementAddress) + sizeof(replacementLength),
                oldProtect,
                &oldProtect);
            FlushInstructionCache(
                GetCurrentProcess(),
                referenceLocation,
                sizeof(replacementAddress) + sizeof(replacementLength));
        }
    }

    for (i = 0; i < g_PatchedLeaCount; ++i)
    {
        unsigned char* instruction = (unsigned char*)g_PatchedLeas[i];
        LONG_PTR displacement64 = (LONG_PTR)((unsigned char*)g_pStaticReplacementSni - (instruction + RIP_RELATIVE_LEA_SIZE));
        if (displacement64 >= LONG_MIN && displacement64 <= LONG_MAX)
        {
            LONG displacement = (LONG)displacement64;
            DWORD oldProtect;
            if (VirtualProtect(instruction, RIP_RELATIVE_LEA_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                memcpy(instruction + 3, &displacement, sizeof(displacement));
                VirtualProtect(instruction, RIP_RELATIVE_LEA_SIZE, oldProtect, &oldProtect);
                FlushInstructionCache(GetCurrentProcess(), instruction, RIP_RELATIVE_LEA_SIZE);
            }
        }
    }

    for (i = 0; i < g_PatchedLengthCount; ++i)
    {
        unsigned char* inst = (unsigned char*)g_PatchedLengths[i];
        SIZE_T offset = 1;
        SIZE_T size = 5;
        DWORD oldProtect;
        DWORD newLen = (DWORD)g_StaticReplacementSniLength;

        if (inst[0] == 0x41)
        {
            offset = 2;
            size = 6;
        }

        if (VirtualProtect(inst, size, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            memcpy(inst + offset, &newLen, sizeof(newLen));
            VirtualProtect(inst, size, oldProtect, &oldProtect);
            FlushInstructionCache(GetCurrentProcess(), inst, size);
        }
    }

    LogMessage("[+] Re-patched %lu LEAs, %lu lengths, %lu string refs with runtime update: %s", 
        g_PatchedLeaCount, g_PatchedLengthCount, g_PatchedStringRefCount, newSni);

    return TRUE;
}

#ifdef __cplusplus
}
#endif
