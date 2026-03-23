/**
 * udp_hook.c - QUIC Initial UDP send hook implementation
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <bcrypt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "udp_hook.h"
#include "hooks.h"
#include "config.h"

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

extern void LogMessage(const char* format, ...);

#ifdef _WIN64
#define JUMP_SIZE 14
#define SENDTO_PATCH_SIZE 15
#define WSASENDTO_PATCH_SIZE 15
#define WSASENDMSG_PATCH_SIZE 18
#define WSAIOCTL_PATCH_SIZE 18
#else
#define JUMP_SIZE 5
#define SENDTO_PATCH_SIZE JUMP_SIZE
#define WSASENDTO_PATCH_SIZE JUMP_SIZE
#define WSASENDMSG_PATCH_SIZE JUMP_SIZE
#define WSAIOCTL_PATCH_SIZE JUMP_SIZE
#endif

#define MAX_PATCH_SIZE 32
#define HOOK_INIT_RETRY_COUNT 50
#define HOOK_INIT_RETRY_DELAY_MS 200
#define HOOK_TRACE_INITIAL_SAMPLES 8
#define HOOK_TRACE_INTERVAL 250
#define QUIC_TARGET_UDP_PORT 443
#define QUIC_PENDING_INITIAL_SLOT_COUNT 4
#define QUIC_PENDING_INITIAL_FLUSH_DELAY_MS 50

#ifndef WARPS_ENABLE_EXPERIMENTAL_WSAMSG_HOOKS
#define WARPS_ENABLE_EXPERIMENTAL_WSAMSG_HOOKS 0
#endif

#ifndef WARPS_ENABLE_STREAM_TLS_REWRITE
#define WARPS_ENABLE_STREAM_TLS_REWRITE 0
#endif

#define QUIC_VERSION_1 0x00000001UL
#define QUIC_VERSION_2 0x6b3343cfUL
#define QUIC_MAX_CONNECTION_ID_LENGTH 20
#define QUIC_MAX_PACKET_NUMBER_LENGTH 4
#define QUIC_MAX_VARINT_LENGTH 8
#define QUIC_HEADER_FORM_LONG 0x80
#define QUIC_FIXED_BIT 0x40
#define QUIC_LONG_PACKET_TYPE_MASK 0x30
#define QUIC_PACKET_TYPE_INITIAL_V1 0x00
#define QUIC_PACKET_TYPE_RETRY_V1 0x30
#define QUIC_PACKET_TYPE_INITIAL_V2 0x10
#define QUIC_PACKET_TYPE_RETRY_V2 0x00
#define QUIC_CRYPTO_FRAME_TYPE 0x06
#define QUIC_PADDING_FRAME_TYPE 0x00
#define QUIC_DATAGRAM_FRAME_TYPE 0x30
#define QUIC_INITIAL_SECRET_LENGTH 32
#define QUIC_AEAD_KEY_LENGTH 16
#define QUIC_AEAD_IV_LENGTH 12
#define QUIC_HP_KEY_LENGTH 16
#define QUIC_AEAD_TAG_LENGTH 16
#define QUIC_HP_SAMPLE_LENGTH 16

static const unsigned char g_QuicV1InitialSalt[] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

static const unsigned char g_QuicV2InitialSalt[] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
};

static const GUID g_WsaIdWSASendMsg = WSAID_WSASENDMSG;

typedef int (WINAPI* WSASendTo_TYPE)(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    const struct sockaddr* lpTo,
    int iTolen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

typedef int (WINAPI* sendto_TYPE)(
    SOCKET s,
    const char* buf,
    int len,
    int flags,
    const struct sockaddr* to,
    int tolen
);

typedef int (WINAPI* send_TYPE)(
    SOCKET s,
    const char* buf,
    int len,
    int flags
);

typedef int (WSAAPI* WSASend_TYPE)(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

typedef int (WSAAPI* WSAIoctl_TYPE)(
    SOCKET s,
    DWORD dwIoControlCode,
    LPVOID lpvInBuffer,
    DWORD cbInBuffer,
    LPVOID lpvOutBuffer,
    DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

typedef struct UDP_HOOK_CONFIG_TAG
{
    const char* label;
    const char* exactName;
    void* detour;
    void** originalStorage;
    SIZE_T patchLength;
    BOOL optional;
} UDP_HOOK_CONFIG;

typedef struct UDP_HOOK_SLOT_TAG
{
    const UDP_HOOK_CONFIG* config;
    unsigned char originalBytes[MAX_PATCH_SIZE];
    unsigned char* target;
    void* trampoline;
    HMODULE module;
    BOOL installed;
    char resolvedName[64];
} UDP_HOOK_SLOT;

typedef struct IAT_HOOK_CONFIG_TAG
{
    const char* label;
    const char* importModule;
    const char* importName;
    void* detour;
    void** originalStorage;
    BOOL optional;
} IAT_HOOK_CONFIG;

typedef struct IAT_HOOK_SLOT_TAG
{
    const IAT_HOOK_CONFIG* config;
    ULONG_PTR* iatEntry;
    ULONG_PTR originalValue;
    BOOL installed;
} IAT_HOOK_SLOT;

typedef struct QUIC_INITIAL_KEYS_TAG
{
    unsigned char packetKey[QUIC_AEAD_KEY_LENGTH];
    unsigned char packetIv[QUIC_AEAD_IV_LENGTH];
    unsigned char hpKey[QUIC_HP_KEY_LENGTH];
} QUIC_INITIAL_KEYS;

typedef struct QUIC_PACKET_METADATA_TAG
{
    DWORD version;
    SIZE_T packetLength;
    SIZE_T pnOffset;
    SIZE_T headerLength;
    SIZE_T ciphertextOffset;
    SIZE_T ciphertextLengthWithTag;
    SIZE_T plaintextLength;
    unsigned char dcid[QUIC_MAX_CONNECTION_ID_LENGTH];
    unsigned char dcidLength;
    unsigned char scidLength;
    unsigned char unprotectedFirstByte;
    unsigned char packetNumberLength;
    unsigned char packetNumberBytes[QUIC_MAX_PACKET_NUMBER_LENGTH];
    ULONGLONG packetNumber;
} QUIC_PACKET_METADATA;

typedef struct QUIC_FRAME_SLICE_TAG
{
    ULONGLONG type;
    SIZE_T offset;
    SIZE_T length;
    BOOL isCrypto;
    ULONGLONG cryptoOffset;
    SIZE_T cryptoLengthFieldOffset;
    SIZE_T cryptoLengthFieldLength;
    SIZE_T cryptoDataOffset;
    SIZE_T cryptoDataLength;
} QUIC_FRAME_SLICE;

typedef struct UDP_SEND_TARGET_TAG
{
    struct sockaddr_storage address;
    int addressLength;
} UDP_SEND_TARGET;

typedef struct UDP_TRACE_CONTEXT_TAG
{
    const UDP_SEND_TARGET* target;
    const unsigned char* datagram;
    SIZE_T datagramLength;
} UDP_TRACE_CONTEXT;

typedef enum UDP_SEND_METHOD_TAG
{
    UDP_SEND_METHOD_SEND = 0,
    UDP_SEND_METHOD_WSASEND,
    UDP_SEND_METHOD_WSASENDTO,
    UDP_SEND_METHOD_WSASENDMSG,
    UDP_SEND_METHOD_SENDTO
} UDP_SEND_METHOD;

typedef enum UDP_SEND_DECISION_TAG
{
    UDP_SEND_DECISION_FALLTHROUGH = 0,
    UDP_SEND_DECISION_BUFFERED,
    UDP_SEND_DECISION_SENT_INTERNAL
} UDP_SEND_DECISION;

typedef struct UDP_SEND_OPERATION_TAG
{
    UDP_SEND_METHOD method;
    SOCKET socketHandle;
    DWORD flags;
    UDP_SEND_TARGET target;
} UDP_SEND_OPERATION;

typedef struct UDP_SEND_RESULT_TAG
{
    int result;
    DWORD bytesSent;
    int lastError;
} UDP_SEND_RESULT;

typedef struct QUIC_CRYPTO_RUN_TAG
{
    QUIC_FRAME_SLICE* frames;
    BOOL* includedCryptoFrames;
    SIZE_T frameCount;
    SIZE_T paddingByteCount;
    SIZE_T replacementFrameIndex;
    SIZE_T consumedCryptoFrameBytes;
    ULONGLONG startOffset;
    SIZE_T contiguousCryptoLength;
} QUIC_CRYPTO_RUN;

typedef struct PREPARED_INITIAL_PACKET_TAG
{
    unsigned char* datagram;
    SIZE_T datagramLength;
    QUIC_PACKET_METADATA metadata;
    QUIC_INITIAL_KEYS keys;
    unsigned char nonce[QUIC_AEAD_IV_LENGTH];
    unsigned char* plaintext;
    QUIC_CRYPTO_RUN cryptoRun;
} PREPARED_INITIAL_PACKET;

typedef struct PENDING_INITIAL_PACKET_TAG
{
    UDP_SEND_OPERATION operation;
    unsigned char* datagram;
    SIZE_T datagramLength;
    DWORD version;
    unsigned char dcid[QUIC_MAX_CONNECTION_ID_LENGTH];
    unsigned char dcidLength;
    ULONGLONG packetNumber;
    ULONGLONG cryptoOffset;
    SIZE_T cryptoLength;
} PENDING_INITIAL_PACKET;

typedef struct PENDING_INITIAL_SLOT_TAG
{
    BOOL active;
    DWORD generation;
    SOCKET socketHandle;
    DWORD version;
    UDP_SEND_TARGET target;
    unsigned char dcid[QUIC_MAX_CONNECTION_ID_LENGTH];
    unsigned char dcidLength;
    PENDING_INITIAL_PACKET packet;
} PENDING_INITIAL_SLOT;

typedef struct PENDING_INITIAL_FLUSH_WORK_TAG
{
    DWORD slotIndex;
    DWORD generation;
} PENDING_INITIAL_FLUSH_WORK;

static HMODULE g_hWs2Module = NULL;
static BOOL g_Ws2LoadedByThisModule = FALSE;
static send_TYPE g_pfnOriginalSend = NULL;
static WSASendTo_TYPE g_pfnOriginalWSASendTo = NULL;
static WSASend_TYPE g_pfnOriginalWSASend = NULL;
static sendto_TYPE g_pfnOriginalSendto = NULL;
static LPFN_WSASENDMSG g_pfnOriginalWSASendMsg = NULL;
static WSAIoctl_TYPE g_pfnOriginalWSAIoctl = NULL;
static BCRYPT_ALG_HANDLE g_hHmacSha256Algorithm = NULL;
static BCRYPT_ALG_HANDLE g_hAesGcmAlgorithm = NULL;
static BCRYPT_ALG_HANDLE g_hAesEcbAlgorithm = NULL;
static ULONG g_HmacObjectLength = 0;
static ULONG g_AesGcmObjectLength = 0;
static ULONG g_AesEcbObjectLength = 0;
static CRITICAL_SECTION g_PendingInitialLock;
static BOOL g_PendingInitialLockInitialized = FALSE;
static PENDING_INITIAL_SLOT g_PendingInitialSlots[QUIC_PENDING_INITIAL_SLOT_COUNT] = { 0 };

static volatile LONG g_sendHitCount = 0;
static volatile LONG g_WSASendToHitCount = 0;
static volatile LONG g_WSASendHitCount = 0;
static volatile LONG g_sendtoHitCount = 0;
static volatile LONG g_WSASendMsgHitCount = 0;
static volatile LONG g_WSASendMsgExtensionHookCount = 0;
static volatile LONG g_AsyncWsasendPassthroughCount = 0;
static volatile LONG g_AsyncWsasendtoPassthroughCount = 0;
static volatile LONG g_AsyncWsasendmsgPassthroughCount = 0;
static volatile LONG g_ShortHeaderPassthroughCount = 0;
static volatile LONG g_UnsupportedVersionPassthroughCount = 0;
static volatile LONG g_NonInitialPassthroughCount = 0;
static volatile LONG g_RetryPassthroughCount = 0;
static volatile LONG g_ParseFailureCount = 0;
static volatile LONG g_NoRewriteCount = 0;
static volatile LONG g_RewriteSuccessCount = 0;

static int WINAPI Hooked_send(
    SOCKET s,
    const char* buf,
    int len,
    int flags);

static int WINAPI Hooked_WSASendTo(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    const struct sockaddr* lpTo,
    int iTolen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

static int WSAAPI Hooked_WSASend(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

static INT WSAAPI Hooked_WSASendMsg(
    SOCKET s,
    LPWSAMSG lpMsg,
    DWORD dwFlags,
    LPDWORD lpNumberOfBytesSent,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

static int WINAPI Hooked_sendto(
    SOCKET s,
    const char* buf,
    int len,
    int flags,
    const struct sockaddr* to,
    int tolen);

static int WSAAPI Hooked_WSAIoctl(
    SOCKET s,
    DWORD dwIoControlCode,
    LPVOID lpvInBuffer,
    DWORD cbInBuffer,
    LPVOID lpvOutBuffer,
    DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

static const UDP_HOOK_CONFIG g_UdpHookConfigs[] = {
    {
        "WSASendTo",
        "WSASendTo",
        (void*)&Hooked_WSASendTo,
        (void**)&g_pfnOriginalWSASendTo,
        WSASENDTO_PATCH_SIZE,
        FALSE
    },
    {
        "sendto",
        "sendto",
        (void*)&Hooked_sendto,
        (void**)&g_pfnOriginalSendto,
        SENDTO_PATCH_SIZE,
        FALSE
    }
#if WARPS_ENABLE_EXPERIMENTAL_WSAMSG_HOOKS
    ,
    {
        "WSASendMsg",
        "WSASendMsg",
        (void*)&Hooked_WSASendMsg,
        (void**)&g_pfnOriginalWSASendMsg,
        WSASENDMSG_PATCH_SIZE,
        TRUE
    },
    {
        "WSAIoctl",
        "WSAIoctl",
        (void*)&Hooked_WSAIoctl,
        (void**)&g_pfnOriginalWSAIoctl,
        WSAIOCTL_PATCH_SIZE,
        FALSE
    }
#endif
};

static UDP_HOOK_SLOT g_UdpHookSlots[
    sizeof(g_UdpHookConfigs) / sizeof(g_UdpHookConfigs[0])] = { 0 };

static const IAT_HOOK_CONFIG g_IatHookConfigs[] = {
    {
        "send",
        "ws2_32.dll",
        "send",
        (void*)&Hooked_send,
        (void**)&g_pfnOriginalSend,
        FALSE
    },
    {
        "sendto",
        "ws2_32.dll",
        "sendto",
        (void*)&Hooked_sendto,
        (void**)&g_pfnOriginalSendto,
        FALSE
    },
    {
        "WSASend",
        "ws2_32.dll",
        "WSASend",
        (void*)&Hooked_WSASend,
        (void**)&g_pfnOriginalWSASend,
        FALSE
    },
    {
        "WSAIoctl",
        "ws2_32.dll",
        "WSAIoctl",
        (void*)&Hooked_WSAIoctl,
        (void**)&g_pfnOriginalWSAIoctl,
        FALSE
    },
    {
        "WSASendTo",
        "ws2_32.dll",
        "WSASendTo",
        (void*)&Hooked_WSASendTo,
        (void**)&g_pfnOriginalWSASendTo,
        TRUE
    }
};

static IAT_HOOK_SLOT g_IatHookSlots[
    sizeof(g_IatHookConfigs) / sizeof(g_IatHookConfigs[0])] = { 0 };

static LONG RegisterHookHit(volatile LONG* counter);
static BOOL ShouldLogHookSample(LONG hitCount);
static BOOL IsSocketType(SOCKET socketHandle, int expectedType);
static BOOL IsDatagramSocket(SOCKET socketHandle);
static BOOL IsStreamSocket(SOCKET socketHandle);
static BOOL ResolveSendTarget(
    SOCKET socketHandle,
    const struct sockaddr* explicitAddress,
    int explicitAddressLength,
    UDP_SEND_TARGET* outTarget);
static USHORT GetSendTargetPort(const UDP_SEND_TARGET* target);
static void FormatSendTarget(
    const UDP_SEND_TARGET* target,
    char* buffer,
    size_t bufferLength);
static void LogPassthroughSample(
    volatile LONG* counter,
    const char* reason,
    const UDP_TRACE_CONTEXT* traceContext);
static unsigned char* CreateModifiedTlsClientHelloCopy(
    const char* hookLabel,
    const UDP_SEND_TARGET* target,
    const unsigned char* data,
    SIZE_T dataLength,
    SIZE_T* outLength);
static DWORD ReadUInt32BE(const unsigned char* data);
static DWORD ReadUInt24BE(const unsigned char* data);
static BOOL UInt64ToSize(ULONGLONG value, SIZE_T* outValue);
static BOOL IsKnownWarpMasqueSni(const char* sni);
static BOOL AreSendTargetsEqual(
    const UDP_SEND_TARGET* left,
    const UDP_SEND_TARGET* right);
static BOOL TryReadVarInt(
    const unsigned char* data,
    SIZE_T available,
    ULONGLONG* value,
    SIZE_T* encodedLength);
static SIZE_T EncodeVarInt(ULONGLONG value, unsigned char* buffer, SIZE_T bufferLength);
static BOOL TryConsumeVarInt(
    const unsigned char* data,
    SIZE_T dataLength,
    SIZE_T* cursor,
    ULONGLONG* value);
static BOOL TryConsumeBytes(SIZE_T dataLength, SIZE_T* cursor, SIZE_T bytesToConsume);
static BOOL InitializeCryptoProviders(void);
static void ReleaseCryptoProviders(void);
static BOOL ComputeHmacSha256(
    const unsigned char* key,
    ULONG keyLength,
    const unsigned char* data,
    ULONG dataLength,
    unsigned char* outDigest,
    ULONG digestLength);
static BOOL HkdfExtractSha256(
    const unsigned char* salt,
    ULONG saltLength,
    const unsigned char* ikm,
    ULONG ikmLength,
    unsigned char* outPrk,
    ULONG prkLength);
static BOOL HkdfExpandSha256(
    const unsigned char* prk,
    ULONG prkLength,
    const unsigned char* info,
    ULONG infoLength,
    unsigned char* outData,
    ULONG outLength);
static BOOL HkdfExpandLabelSha256(
    const unsigned char* secret,
    ULONG secretLength,
    const char* label,
    unsigned char* outData,
    ULONG outLength);
static BOOL DeriveClientInitialKeys(
    DWORD version,
    const unsigned char* dcid,
    unsigned char dcidLength,
    QUIC_INITIAL_KEYS* keys);
static BOOL GenerateSymmetricKey(
    BCRYPT_ALG_HANDLE algorithm,
    ULONG objectLength,
    const unsigned char* keyBytes,
    ULONG keyLength,
    BCRYPT_KEY_HANDLE* outKey,
    unsigned char** outKeyObject);
static BOOL ComputeHeaderProtectionMask(
    const unsigned char* hpKey,
    const unsigned char* sample,
    unsigned char* outMask,
    SIZE_T outMaskLength);
static void BuildPacketNonce(
    const unsigned char* packetIv,
    ULONGLONG packetNumber,
    unsigned char* outNonce);
static BOOL DecryptAes128Gcm(
    const unsigned char* key,
    const unsigned char* nonce,
    const unsigned char* aad,
    ULONG aadLength,
    const unsigned char* ciphertext,
    ULONG ciphertextLength,
    const unsigned char* tag,
    unsigned char* outPlaintext);
static BOOL EncryptAes128Gcm(
    const unsigned char* key,
    const unsigned char* nonce,
    const unsigned char* aad,
    ULONG aadLength,
    const unsigned char* plaintext,
    ULONG plaintextLength,
    unsigned char* outCiphertext,
    unsigned char* outTag);
static void WriteJumpInstruction(unsigned char* source, const void* destination);
static void ResetHookSlot(UDP_HOOK_SLOT* slot);
static BOOL InstallInlineHook(
    UDP_HOOK_SLOT* slot,
    void* target,
    void* detour,
    void** originalStorage);
static void ResetIatHookSlot(IAT_HOOK_SLOT* slot);
static BOOL ValidatePeImageForIatHooks(HMODULE module);
static BOOL InstallIatHooks(HMODULE module, DWORD* outInstalledCount);
static BOOL InstallSingleIatHook(HMODULE module, IAT_HOOK_SLOT* slot);
static BOOL StringEqualsInsensitive(const char* left, const char* right);
static BOOL IsSupportedVersion(DWORD version);
static BOOL IsInitialPacketType(DWORD version, unsigned char firstByte);
static BOOL IsRetryPacketType(DWORD version, unsigned char firstByte);
static BOOL TryParseProtectedInitialPacket(
    const unsigned char* packet,
    SIZE_T packetLength,
    QUIC_PACKET_METADATA* metadata,
    const UDP_TRACE_CONTEXT* traceContext);
static BOOL RemoveHeaderProtection(
    unsigned char* packet,
    const QUIC_INITIAL_KEYS* keys,
    QUIC_PACKET_METADATA* metadata);
static void ApplyHeaderProtection(
    unsigned char* packet,
    const QUIC_INITIAL_KEYS* keys,
    const QUIC_PACKET_METADATA* metadata);
static BOOL TryParseAckFrame(
    const unsigned char* payload,
    SIZE_T payloadLength,
    SIZE_T* cursor,
    BOOL withEcn);
static BOOL TryParseQuicFrame(
    const unsigned char* payload,
    SIZE_T payloadLength,
    SIZE_T frameOffset,
    QUIC_FRAME_SLICE* frame);
static void FreeQuicCryptoRun(QUIC_CRYPTO_RUN* run);
static BOOL TryCollectCryptoRun(
    const unsigned char* payload,
    SIZE_T payloadLength,
    QUIC_CRYPTO_RUN* run);
static unsigned char* CopyCryptoRunBytes(
    const unsigned char* payload,
    const QUIC_CRYPTO_RUN* run);
static BOOL BuildRewrittenPayloadFromCryptoRun(
    const unsigned char* payload,
    SIZE_T payloadLength,
    const QUIC_CRYPTO_RUN* run,
    ULONGLONG replacementOffset,
    const unsigned char* replacementCrypto,
    SIZE_T replacementCryptoLength,
    unsigned char** outRewrittenPayload);
static BOOL TryRewriteInitialPayload(
    const unsigned char* payload,
    SIZE_T payloadLength,
    unsigned char** outRewrittenPayload,
    const UDP_TRACE_CONTEXT* traceContext);
static void FreePreparedInitialPacket(PREPARED_INITIAL_PACKET* prepared);
static BOOL TryPrepareInitialPacket(
    const unsigned char* datagram,
    SIZE_T datagramLength,
    const UDP_TRACE_CONTEXT* traceContext,
    PREPARED_INITIAL_PACKET* prepared);
static BOOL ApplyRewrittenPayloadToPreparedInitial(
    PREPARED_INITIAL_PACKET* prepared,
    const unsigned char* rewrittenPayload);
static BOOL TryRewriteDatagramInPlace(
    unsigned char* datagram,
    SIZE_T datagramLength,
    const UDP_TRACE_CONTEXT* traceContext);
static unsigned char* FlattenWsabufs(
    const WSABUF* buffers,
    DWORD bufferCount,
    SIZE_T* outLength);
static int SendDatagramWithOperation(
    const UDP_SEND_OPERATION* operation,
    const unsigned char* datagram,
    SIZE_T datagramLength,
    UDP_SEND_RESULT* outResult);
static void FreePendingInitialPacket(PENDING_INITIAL_PACKET* packet);
static void ResetPendingInitialSlot(PENDING_INITIAL_SLOT* slot);
static DWORD WINAPI PendingInitialFlushWorker(LPVOID context);
static BOOL TrySchedulePendingInitialFlush(DWORD slotIndex, DWORD generation);
static BOOL TryTakeMatchingPendingInitial(
    const UDP_SEND_OPERATION* operation,
    DWORD version,
    const unsigned char* dcid,
    unsigned char dcidLength,
    ULONGLONG cryptoOffset,
    SIZE_T cryptoLength,
    PENDING_INITIAL_PACKET* outPacket);
static BOOL TryBufferPendingInitial(
    const UDP_SEND_OPERATION* operation,
    unsigned char** datagram,
    SIZE_T datagramLength,
    DWORD version,
    const unsigned char* dcid,
    unsigned char dcidLength,
    ULONGLONG packetNumber,
    ULONGLONG cryptoOffset,
    SIZE_T cryptoLength,
    const char* observedSni,
    SIZE_T availableClientHelloLength,
    SIZE_T declaredClientHelloLength);
static BOOL TryGetTruncatedClientHelloPrefix(
    const unsigned char* crypto,
    SIZE_T cryptoLength,
    SIZE_T* outAvailableClientHelloLength,
    SIZE_T* outDeclaredClientHelloLength);
static BOOL TrySendBufferedRewritePair(
    const PENDING_INITIAL_PACKET* pendingPacket,
    const UDP_SEND_OPERATION* currentOperation,
    const unsigned char* currentDatagram,
    SIZE_T currentDatagramLength,
    PREPARED_INITIAL_PACKET* currentPrepared,
    const UDP_TRACE_CONTEXT* traceContext,
    UDP_SEND_RESULT* outCurrentResult);
static UDP_SEND_DECISION TryHandleBufferedInitialRewrite(
    const UDP_SEND_OPERATION* operation,
    unsigned char** datagram,
    SIZE_T datagramLength,
    const UDP_TRACE_CONTEXT* traceContext,
    UDP_SEND_RESULT* outCurrentResult);

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

static BOOL IsSocketType(SOCKET socketHandle, int expectedType)
{
    int socketType = 0;
    int optionLength = sizeof(socketType);

    return getsockopt(
               socketHandle,
               SOL_SOCKET,
               SO_TYPE,
               (char*)&socketType,
               &optionLength) == 0 &&
           optionLength == sizeof(socketType) &&
           socketType == expectedType;
}

static BOOL IsDatagramSocket(SOCKET socketHandle)
{
    return IsSocketType(socketHandle, SOCK_DGRAM);
}

static BOOL IsStreamSocket(SOCKET socketHandle)
{
    return IsSocketType(socketHandle, SOCK_STREAM);
}

static BOOL ResolveSendTarget(
    SOCKET socketHandle,
    const struct sockaddr* explicitAddress,
    int explicitAddressLength,
    UDP_SEND_TARGET* outTarget)
{
    int peerLength;

    if (!outTarget)
    {
        return FALSE;
    }

    memset(outTarget, 0, sizeof(*outTarget));
    if (explicitAddress && explicitAddressLength > 0)
    {
        outTarget->addressLength = explicitAddressLength;
        if (outTarget->addressLength > (int)sizeof(outTarget->address))
        {
            outTarget->addressLength = sizeof(outTarget->address);
        }

        memcpy(&outTarget->address, explicitAddress, outTarget->addressLength);
        return TRUE;
    }

    peerLength = sizeof(outTarget->address);
    if (getpeername(
            socketHandle,
            (struct sockaddr*)&outTarget->address,
            &peerLength) == 0 &&
        peerLength > 0)
    {
        outTarget->addressLength = peerLength;
        return TRUE;
    }

    return FALSE;
}

static USHORT GetSendTargetPort(const UDP_SEND_TARGET* target)
{
    if (!target || target->addressLength <= 0)
    {
        return 0;
    }

    if (target->address.ss_family == AF_INET &&
        target->addressLength >= (int)sizeof(struct sockaddr_in))
    {
        return ntohs(((const struct sockaddr_in*)&target->address)->sin_port);
    }

    if (target->address.ss_family == AF_INET6 &&
        target->addressLength >= (int)sizeof(struct sockaddr_in6))
    {
        return ntohs(((const struct sockaddr_in6*)&target->address)->sin6_port);
    }

    return 0;
}

static void FormatSendTarget(
    const UDP_SEND_TARGET* target,
    char* buffer,
    size_t bufferLength)
{
    char addressText[INET6_ADDRSTRLEN];

    if (!buffer || bufferLength == 0)
    {
        return;
    }

    buffer[0] = '\0';
    if (!target || target->addressLength <= 0)
    {
        strncpy_s(buffer, bufferLength, "unresolved", _TRUNCATE);
        return;
    }

    if (target->address.ss_family == AF_INET &&
        target->addressLength >= (int)sizeof(struct sockaddr_in))
    {
        const struct sockaddr_in* ipv4 = (const struct sockaddr_in*)&target->address;
        if (!InetNtopA(AF_INET, &ipv4->sin_addr, addressText, sizeof(addressText)))
        {
            strncpy_s(addressText, sizeof(addressText), "unknown", _TRUNCATE);
        }

        _snprintf_s(
            buffer,
            bufferLength,
            _TRUNCATE,
            "%s:%u",
            addressText,
            (unsigned int)ntohs(ipv4->sin_port));
        return;
    }

    if (target->address.ss_family == AF_INET6 &&
        target->addressLength >= (int)sizeof(struct sockaddr_in6))
    {
        const struct sockaddr_in6* ipv6 = (const struct sockaddr_in6*)&target->address;
        if (!InetNtopA(AF_INET6, &ipv6->sin6_addr, addressText, sizeof(addressText)))
        {
            strncpy_s(addressText, sizeof(addressText), "unknown", _TRUNCATE);
        }

        _snprintf_s(
            buffer,
            bufferLength,
            _TRUNCATE,
            "[%s]:%u",
            addressText,
            (unsigned int)ntohs(ipv6->sin6_port));
        return;
    }

    _snprintf_s(
        buffer,
        bufferLength,
        _TRUNCATE,
        "af=%d",
        (int)target->address.ss_family);
}

static void LogPassthroughSample(
    volatile LONG* counter,
    const char* reason,
    const UDP_TRACE_CONTEXT* traceContext)
{
    LONG hitCount = RegisterHookHit(counter);
    char destinationText[96];

    if (reason && ShouldLogHookSample(hitCount))
    {
        FormatSendTarget(
            traceContext ? traceContext->target : NULL,
            destinationText,
            sizeof(destinationText));

        if (traceContext &&
            traceContext->datagram &&
            traceContext->datagramLength > 0)
        {
            unsigned char firstByte = traceContext->datagram[0];

            if ((firstByte & QUIC_HEADER_FORM_LONG) != 0 &&
                traceContext->datagramLength >= 5)
            {
                LogMessage(
                    "[*] UDP passthrough: %s (sample #%ld, dst=%s, len=%u, first=0x%02x, version=0x%08lx)",
                    reason,
                    hitCount,
                    destinationText,
                    (unsigned int)traceContext->datagramLength,
                    firstByte,
                    (unsigned long)ReadUInt32BE(traceContext->datagram + 1));
                return;
            }

            LogMessage(
                "[*] UDP passthrough: %s (sample #%ld, dst=%s, len=%u, first=0x%02x)",
                reason,
                hitCount,
                destinationText,
                (unsigned int)traceContext->datagramLength,
                firstByte);
            return;
        }

        LogMessage(
            "[*] UDP passthrough: %s (sample #%ld, dst=%s)",
            reason,
            hitCount,
            destinationText);
    }
}

static unsigned char* CreateModifiedTlsClientHelloCopy(
    const char* hookLabel,
    const UDP_SEND_TARGET* target,
    const unsigned char* data,
    SIZE_T dataLength,
    SIZE_T* outLength)
{
    unsigned char* copiedData;
    unsigned char* modifiedData;
    SIZE_T modifiedLength;
    char configuredSni[MAX_PATH];
    char observedSni[MAX_PATH];
    const char* observedKind = "unknown";
    char destinationText[96];

    if (outLength)
    {
        *outLength = 0;
    }

    if (!hookLabel || !data || dataLength == 0 || !outLength)
    {
        return NULL;
    }

    if (!IsClientHelloBuffer(data, dataLength))
    {
        return NULL;
    }

    FormatSendTarget(target, destinationText, sizeof(destinationText));
    if (TryExtractObservedSni(
            data,
            dataLength,
            observedSni,
            sizeof(observedSni),
            &observedKind))
    {
        LogMessage(
            "[*] %s observed TLS ClientHello SNI before rewrite (%s, dst=%s): %s",
            hookLabel,
            observedKind,
            destinationText,
            observedSni);
    }
    else
    {
        LogMessage(
            "[*] %s observed TLS ClientHello without a parsable SNI (dst=%s, len=%u)",
            hookLabel,
            destinationText,
            (unsigned int)dataLength);
    }

    copiedData = (unsigned char*)malloc(dataLength);
    if (!copiedData)
    {
        LogMessage(
            "[!] %s failed to allocate a temporary TLS ClientHello copy (%u bytes)",
            hookLabel,
            (unsigned int)dataLength);
        return NULL;
    }

    memcpy(copiedData, data, dataLength);
    modifiedLength = dataLength;
    if (!Config_CopySNI(configuredSni, sizeof(configuredSni)))
    {
        free(copiedData);
        return NULL;
    }
    modifiedData = ModifyClientHelloSNI(copiedData, &modifiedLength, configuredSni);
    if (!modifiedData)
    {
        free(copiedData);
        return NULL;
    }

    if (modifiedData != copiedData)
    {
        free(copiedData);
    }

    if (modifiedLength == dataLength &&
        memcmp(modifiedData, data, dataLength) == 0)
    {
        LogMessage(
            "[*] %s left TLS ClientHello unchanged (dst=%s)",
            hookLabel,
            destinationText);
        free(modifiedData);
        return NULL;
    }

    *outLength = modifiedLength;
    LogMessage(
        "[+] %s rewrote TLS ClientHello SNI (dst=%s, %u -> %u bytes)",
        hookLabel,
        destinationText,
        (unsigned int)dataLength,
        (unsigned int)modifiedLength);
    return modifiedData;
}

static DWORD ReadUInt32BE(const unsigned char* data)
{
    if (!data)
    {
        return 0;
    }

    return ((DWORD)data[0] << 24) |
           ((DWORD)data[1] << 16) |
           ((DWORD)data[2] << 8) |
           (DWORD)data[3];
}

static DWORD ReadUInt24BE(const unsigned char* data)
{
    if (!data)
    {
        return 0;
    }

    return ((DWORD)data[0] << 16) |
           ((DWORD)data[1] << 8) |
           (DWORD)data[2];
}

static BOOL IsKnownWarpMasqueSni(const char* sni)
{
    static const char* const knownSnis[] = {
        "consumer-masque.cloudflareclient.com",
        "consumer-masque.cloudflareclient.com.",
        "consumer-masque-proxy.cloudflareclient.com",
        "consumer-masque-proxy.cloudflareclient.com.",
        "zt-masque.cloudflareclient.com",
        "zt-masque.cloudflareclient.com.",
        "zt-masque-proxy.cloudflareclient.com",
        "zt-masque-proxy.cloudflareclient.com."
    };
    SIZE_T index;

    if (!sni || sni[0] == '\0')
    {
        return FALSE;
    }

    for (index = 0; index < sizeof(knownSnis) / sizeof(knownSnis[0]); ++index)
    {
        if (_stricmp(sni, knownSnis[index]) == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOL AreSendTargetsEqual(
    const UDP_SEND_TARGET* left,
    const UDP_SEND_TARGET* right)
{
    if (!left || !right || left->addressLength != right->addressLength)
    {
        return FALSE;
    }

    if (left->addressLength <= 0 ||
        left->address.ss_family != right->address.ss_family)
    {
        return FALSE;
    }

    return memcmp(&left->address, &right->address, (size_t)left->addressLength) == 0;
}

static BOOL UInt64ToSize(ULONGLONG value, SIZE_T* outValue)
{
    if (!outValue)
    {
        return FALSE;
    }

    if (value > (ULONGLONG)((SIZE_T)-1))
    {
        return FALSE;
    }

    *outValue = (SIZE_T)value;
    return TRUE;
}

static BOOL TryReadVarInt(
    const unsigned char* data,
    SIZE_T available,
    ULONGLONG* value,
    SIZE_T* encodedLength)
{
    ULONGLONG result;
    SIZE_T length;
    SIZE_T index;

    if (!data || available == 0)
    {
        return FALSE;
    }

    length = (SIZE_T)1 << (data[0] >> 6);
    if (length > available)
    {
        return FALSE;
    }

    result = (ULONGLONG)(data[0] & 0x3f);
    for (index = 1; index < length; ++index)
    {
        result = (result << 8) | data[index];
    }

    if (value)
    {
        *value = result;
    }

    if (encodedLength)
    {
        *encodedLength = length;
    }

    return TRUE;
}

static SIZE_T EncodeVarInt(ULONGLONG value, unsigned char* buffer, SIZE_T bufferLength)
{
    SIZE_T encodedLength;
    SIZE_T index;

    if (value <= 63)
    {
        encodedLength = 1;
    }
    else if (value <= 16383)
    {
        encodedLength = 2;
    }
    else if (value <= 1073741823ULL)
    {
        encodedLength = 4;
    }
    else if (value <= 4611686018427387903ULL)
    {
        encodedLength = 8;
    }
    else
    {
        return 0;
    }

    if (!buffer || bufferLength < encodedLength)
    {
        return 0;
    }

    for (index = 0; index < encodedLength; ++index)
    {
        buffer[encodedLength - index - 1] = (unsigned char)(value & 0xff);
        value >>= 8;
    }

    switch (encodedLength)
    {
    case 1:
        buffer[0] |= 0x00;
        break;
    case 2:
        buffer[0] |= 0x40;
        break;
    case 4:
        buffer[0] |= 0x80;
        break;
    case 8:
        buffer[0] |= 0xc0;
        break;
    default:
        return 0;
    }

    return encodedLength;
}

static BOOL TryConsumeVarInt(
    const unsigned char* data,
    SIZE_T dataLength,
    SIZE_T* cursor,
    ULONGLONG* value)
{
    SIZE_T encodedLength;
    ULONGLONG decodedValue;

    if (!data || !cursor || *cursor > dataLength)
    {
        return FALSE;
    }

    if (!TryReadVarInt(data + *cursor, dataLength - *cursor, &decodedValue, &encodedLength))
    {
        return FALSE;
    }

    *cursor += encodedLength;
    if (value)
    {
        *value = decodedValue;
    }

    return TRUE;
}

static BOOL TryConsumeBytes(SIZE_T dataLength, SIZE_T* cursor, SIZE_T bytesToConsume)
{
    if (!cursor || *cursor > dataLength || bytesToConsume > dataLength - *cursor)
    {
        return FALSE;
    }

    *cursor += bytesToConsume;
    return TRUE;
}

static BOOL InitializeCryptoProviders(void)
{
    NTSTATUS status;
    ULONG resultLength;

    if (g_hHmacSha256Algorithm && g_hAesGcmAlgorithm && g_hAesEcbAlgorithm)
    {
        return TRUE;
    }

    status = BCryptOpenAlgorithmProvider(
        &g_hHmacSha256Algorithm,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status))
    {
        LogMessage("[!] BCryptOpenAlgorithmProvider(SHA256/HMAC) failed: 0x%08lx", (unsigned long)status);
        ReleaseCryptoProviders();
        return FALSE;
    }

    status = BCryptGetProperty(
        g_hHmacSha256Algorithm,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&g_HmacObjectLength,
        sizeof(g_HmacObjectLength),
        &resultLength,
        0);
    if (!NT_SUCCESS(status))
    {
        LogMessage("[!] BCryptGetProperty(HMAC object length) failed: 0x%08lx", (unsigned long)status);
        ReleaseCryptoProviders();
        return FALSE;
    }

    status = BCryptOpenAlgorithmProvider(
        &g_hAesGcmAlgorithm,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
        LogMessage("[!] BCryptOpenAlgorithmProvider(AES/GCM) failed: 0x%08lx", (unsigned long)status);
        ReleaseCryptoProviders();
        return FALSE;
    }

    status = BCryptSetProperty(
        g_hAesGcmAlgorithm,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM),
        0);
    if (!NT_SUCCESS(status))
    {
        LogMessage("[!] BCryptSetProperty(AES/GCM chain mode) failed: 0x%08lx", (unsigned long)status);
        ReleaseCryptoProviders();
        return FALSE;
    }

    status = BCryptGetProperty(
        g_hAesGcmAlgorithm,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&g_AesGcmObjectLength,
        sizeof(g_AesGcmObjectLength),
        &resultLength,
        0);
    if (!NT_SUCCESS(status))
    {
        LogMessage("[!] BCryptGetProperty(AES/GCM object length) failed: 0x%08lx", (unsigned long)status);
        ReleaseCryptoProviders();
        return FALSE;
    }

    status = BCryptOpenAlgorithmProvider(
        &g_hAesEcbAlgorithm,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
        LogMessage("[!] BCryptOpenAlgorithmProvider(AES/ECB) failed: 0x%08lx", (unsigned long)status);
        ReleaseCryptoProviders();
        return FALSE;
    }

    status = BCryptSetProperty(
        g_hAesEcbAlgorithm,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
        sizeof(BCRYPT_CHAIN_MODE_ECB),
        0);
    if (!NT_SUCCESS(status))
    {
        LogMessage("[!] BCryptSetProperty(AES/ECB chain mode) failed: 0x%08lx", (unsigned long)status);
        ReleaseCryptoProviders();
        return FALSE;
    }

    status = BCryptGetProperty(
        g_hAesEcbAlgorithm,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&g_AesEcbObjectLength,
        sizeof(g_AesEcbObjectLength),
        &resultLength,
        0);
    if (!NT_SUCCESS(status))
    {
        LogMessage("[!] BCryptGetProperty(AES/ECB object length) failed: 0x%08lx", (unsigned long)status);
        ReleaseCryptoProviders();
        return FALSE;
    }

    return TRUE;
}

static void ReleaseCryptoProviders(void)
{
    if (g_hAesEcbAlgorithm)
    {
        BCryptCloseAlgorithmProvider(g_hAesEcbAlgorithm, 0);
        g_hAesEcbAlgorithm = NULL;
    }

    if (g_hAesGcmAlgorithm)
    {
        BCryptCloseAlgorithmProvider(g_hAesGcmAlgorithm, 0);
        g_hAesGcmAlgorithm = NULL;
    }

    if (g_hHmacSha256Algorithm)
    {
        BCryptCloseAlgorithmProvider(g_hHmacSha256Algorithm, 0);
        g_hHmacSha256Algorithm = NULL;
    }

    g_HmacObjectLength = 0;
    g_AesGcmObjectLength = 0;
    g_AesEcbObjectLength = 0;
}

static BOOL ComputeHmacSha256(
    const unsigned char* key,
    ULONG keyLength,
    const unsigned char* data,
    ULONG dataLength,
    unsigned char* outDigest,
    ULONG digestLength)
{
    BCRYPT_HASH_HANDLE hashHandle = NULL;
    unsigned char* hashObject = NULL;
    NTSTATUS status;
    BOOL success = FALSE;

    if (!outDigest || digestLength != QUIC_INITIAL_SECRET_LENGTH || !g_hHmacSha256Algorithm)
    {
        return FALSE;
    }

    hashObject = (unsigned char*)malloc(g_HmacObjectLength);
    if (!hashObject)
    {
        return FALSE;
    }

    status = BCryptCreateHash(
        g_hHmacSha256Algorithm,
        &hashHandle,
        hashObject,
        g_HmacObjectLength,
        (PUCHAR)key,
        keyLength,
        0);
    if (!NT_SUCCESS(status))
    {
        LogMessage("[!] BCryptCreateHash(HMAC) failed: 0x%08lx", (unsigned long)status);
        goto Cleanup;
    }

    if (data && dataLength > 0)
    {
        status = BCryptHashData(hashHandle, (PUCHAR)data, dataLength, 0);
        if (!NT_SUCCESS(status))
        {
            LogMessage("[!] BCryptHashData(HMAC) failed: 0x%08lx", (unsigned long)status);
            goto Cleanup;
        }
    }

    status = BCryptFinishHash(hashHandle, outDigest, digestLength, 0);
    if (!NT_SUCCESS(status))
    {
        LogMessage("[!] BCryptFinishHash(HMAC) failed: 0x%08lx", (unsigned long)status);
        goto Cleanup;
    }

    success = TRUE;

Cleanup:
    if (hashHandle)
    {
        BCryptDestroyHash(hashHandle);
    }

    if (hashObject)
    {
        free(hashObject);
    }

    return success;
}

static BOOL HkdfExtractSha256(
    const unsigned char* salt,
    ULONG saltLength,
    const unsigned char* ikm,
    ULONG ikmLength,
    unsigned char* outPrk,
    ULONG prkLength)
{
    return ComputeHmacSha256(salt, saltLength, ikm, ikmLength, outPrk, prkLength);
}

static BOOL HkdfExpandSha256(
    const unsigned char* prk,
    ULONG prkLength,
    const unsigned char* info,
    ULONG infoLength,
    unsigned char* outData,
    ULONG outLength)
{
    unsigned char previousBlock[QUIC_INITIAL_SECRET_LENGTH];
    unsigned char hashInput[QUIC_INITIAL_SECRET_LENGTH + 64];
    ULONG previousLength = 0;
    ULONG produced = 0;
    unsigned char counter = 1;

    if (!prk || !outData || outLength == 0)
    {
        return FALSE;
    }

    if (infoLength > sizeof(hashInput) - QUIC_INITIAL_SECRET_LENGTH - 1)
    {
        return FALSE;
    }

    while (produced < outLength)
    {
        ULONG hashInputLength;
        ULONG bytesToCopy;

        if (previousLength > 0)
        {
            memcpy(hashInput, previousBlock, previousLength);
        }

        if (info && infoLength > 0)
        {
            memcpy(hashInput + previousLength, info, infoLength);
        }

        hashInput[previousLength + infoLength] = counter;
        hashInputLength = previousLength + infoLength + 1;

        if (!ComputeHmacSha256(
                prk,
                prkLength,
                hashInput,
                hashInputLength,
                previousBlock,
                sizeof(previousBlock)))
        {
            return FALSE;
        }

        previousLength = sizeof(previousBlock);
        bytesToCopy = outLength - produced;
        if (bytesToCopy > sizeof(previousBlock))
        {
            bytesToCopy = sizeof(previousBlock);
        }

        memcpy(outData + produced, previousBlock, bytesToCopy);
        produced += bytesToCopy;
        counter++;
    }

    return TRUE;
}

static BOOL HkdfExpandLabelSha256(
    const unsigned char* secret,
    ULONG secretLength,
    const char* label,
    unsigned char* outData,
    ULONG outLength)
{
    static const char tls13Prefix[] = "tls13 ";
    unsigned char info[64];
    size_t labelLength;
    size_t fullLabelLength;

    if (!secret || !label || !outData)
    {
        return FALSE;
    }

    labelLength = strlen(label);
    fullLabelLength = sizeof(tls13Prefix) - 1 + labelLength;
    if (fullLabelLength > 255 || fullLabelLength + 4 > sizeof(info))
    {
        return FALSE;
    }

    info[0] = (unsigned char)((outLength >> 8) & 0xff);
    info[1] = (unsigned char)(outLength & 0xff);
    info[2] = (unsigned char)fullLabelLength;
    memcpy(info + 3, tls13Prefix, sizeof(tls13Prefix) - 1);
    memcpy(info + 3 + sizeof(tls13Prefix) - 1, label, labelLength);
    info[3 + fullLabelLength] = 0;

    return HkdfExpandSha256(
        secret,
        secretLength,
        info,
        (ULONG)(4 + fullLabelLength),
        outData,
        outLength);
}

static BOOL DeriveClientInitialKeys(
    DWORD version,
    const unsigned char* dcid,
    unsigned char dcidLength,
    QUIC_INITIAL_KEYS* keys)
{
    const unsigned char* salt;
    size_t saltLength;
    const char* keyLabel;
    const char* ivLabel;
    const char* hpLabel;
    unsigned char initialSecret[QUIC_INITIAL_SECRET_LENGTH];
    unsigned char clientInitialSecret[QUIC_INITIAL_SECRET_LENGTH];

    if (!keys || (!dcid && dcidLength > 0))
    {
        return FALSE;
    }

    if (version == QUIC_VERSION_1)
    {
        salt = g_QuicV1InitialSalt;
        saltLength = sizeof(g_QuicV1InitialSalt);
        keyLabel = "quic key";
        ivLabel = "quic iv";
        hpLabel = "quic hp";
    }
    else if (version == QUIC_VERSION_2)
    {
        salt = g_QuicV2InitialSalt;
        saltLength = sizeof(g_QuicV2InitialSalt);
        keyLabel = "quicv2 key";
        ivLabel = "quicv2 iv";
        hpLabel = "quicv2 hp";
    }
    else
    {
        return FALSE;
    }

    if (!HkdfExtractSha256(
            salt,
            (ULONG)saltLength,
            dcid,
            dcidLength,
            initialSecret,
            sizeof(initialSecret)) ||
        !HkdfExpandLabelSha256(
            initialSecret,
            sizeof(initialSecret),
            "client in",
            clientInitialSecret,
            sizeof(clientInitialSecret)) ||
        !HkdfExpandLabelSha256(
            clientInitialSecret,
            sizeof(clientInitialSecret),
            keyLabel,
            keys->packetKey,
            sizeof(keys->packetKey)) ||
        !HkdfExpandLabelSha256(
            clientInitialSecret,
            sizeof(clientInitialSecret),
            ivLabel,
            keys->packetIv,
            sizeof(keys->packetIv)) ||
        !HkdfExpandLabelSha256(
            clientInitialSecret,
            sizeof(clientInitialSecret),
            hpLabel,
            keys->hpKey,
            sizeof(keys->hpKey)))
    {
        LogMessage("[!] Failed to derive QUIC Initial keys");
        return FALSE;
    }

    SecureZeroMemory(initialSecret, sizeof(initialSecret));
    SecureZeroMemory(clientInitialSecret, sizeof(clientInitialSecret));
    return TRUE;
}

static BOOL GenerateSymmetricKey(
    BCRYPT_ALG_HANDLE algorithm,
    ULONG objectLength,
    const unsigned char* keyBytes,
    ULONG keyLength,
    BCRYPT_KEY_HANDLE* outKey,
    unsigned char** outKeyObject)
{
    unsigned char* keyObject = NULL;
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    NTSTATUS status;

    if (!algorithm || !keyBytes || !outKey || !outKeyObject)
    {
        return FALSE;
    }

    keyObject = (unsigned char*)malloc(objectLength);
    if (!keyObject)
    {
        return FALSE;
    }

    status = BCryptGenerateSymmetricKey(
        algorithm,
        &keyHandle,
        keyObject,
        objectLength,
        (PUCHAR)keyBytes,
        keyLength,
        0);
    if (!NT_SUCCESS(status))
    {
        LogMessage("[!] BCryptGenerateSymmetricKey failed: 0x%08lx", (unsigned long)status);
        free(keyObject);
        return FALSE;
    }

    *outKey = keyHandle;
    *outKeyObject = keyObject;
    return TRUE;
}

static BOOL ComputeHeaderProtectionMask(
    const unsigned char* hpKey,
    const unsigned char* sample,
    unsigned char* outMask,
    SIZE_T outMaskLength)
{
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    unsigned char* keyObject = NULL;
    NTSTATUS status;
    ULONG resultLength = 0;
    BOOL success = FALSE;

    if (!hpKey || !sample || !outMask || outMaskLength < QUIC_HP_SAMPLE_LENGTH)
    {
        return FALSE;
    }

    if (!GenerateSymmetricKey(
            g_hAesEcbAlgorithm,
            g_AesEcbObjectLength,
            hpKey,
            QUIC_HP_KEY_LENGTH,
            &keyHandle,
            &keyObject))
    {
        return FALSE;
    }

    status = BCryptEncrypt(
        keyHandle,
        (PUCHAR)sample,
        QUIC_HP_SAMPLE_LENGTH,
        NULL,
        NULL,
        0,
        outMask,
        (ULONG)outMaskLength,
        &resultLength,
        0);
    if (!NT_SUCCESS(status) || resultLength < QUIC_HP_SAMPLE_LENGTH)
    {
        LogMessage("[!] BCryptEncrypt(AES-ECB header protection) failed: 0x%08lx", (unsigned long)status);
        goto Cleanup;
    }

    success = TRUE;

Cleanup:
    if (keyHandle)
    {
        BCryptDestroyKey(keyHandle);
    }

    if (keyObject)
    {
        free(keyObject);
    }

    return success;
}

static void BuildPacketNonce(
    const unsigned char* packetIv,
    ULONGLONG packetNumber,
    unsigned char* outNonce)
{
    int index;

    memcpy(outNonce, packetIv, QUIC_AEAD_IV_LENGTH);

    for (index = 0; index < 8; ++index)
    {
        outNonce[QUIC_AEAD_IV_LENGTH - index - 1] ^= (unsigned char)(packetNumber & 0xff);
        packetNumber >>= 8;
    }
}

static BOOL DecryptAes128Gcm(
    const unsigned char* key,
    const unsigned char* nonce,
    const unsigned char* aad,
    ULONG aadLength,
    const unsigned char* ciphertext,
    ULONG ciphertextLength,
    const unsigned char* tag,
    unsigned char* outPlaintext)
{
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    unsigned char* keyObject = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    NTSTATUS status;
    ULONG resultLength = 0;
    BOOL success = FALSE;

    if (!key || !nonce || !ciphertext || !tag || !outPlaintext)
    {
        return FALSE;
    }

    if (!GenerateSymmetricKey(
            g_hAesGcmAlgorithm,
            g_AesGcmObjectLength,
            key,
            QUIC_AEAD_KEY_LENGTH,
            &keyHandle,
            &keyObject))
    {
        return FALSE;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = QUIC_AEAD_IV_LENGTH;
    authInfo.pbAuthData = (PUCHAR)aad;
    authInfo.cbAuthData = aadLength;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = QUIC_AEAD_TAG_LENGTH;

    status = BCryptDecrypt(
        keyHandle,
        (PUCHAR)ciphertext,
        ciphertextLength,
        &authInfo,
        NULL,
        0,
        outPlaintext,
        ciphertextLength,
        &resultLength,
        0);
    if (!NT_SUCCESS(status) || resultLength != ciphertextLength)
    {
        goto Cleanup;
    }

    success = TRUE;

Cleanup:
    if (keyHandle)
    {
        BCryptDestroyKey(keyHandle);
    }

    if (keyObject)
    {
        free(keyObject);
    }

    return success;
}

static BOOL EncryptAes128Gcm(
    const unsigned char* key,
    const unsigned char* nonce,
    const unsigned char* aad,
    ULONG aadLength,
    const unsigned char* plaintext,
    ULONG plaintextLength,
    unsigned char* outCiphertext,
    unsigned char* outTag)
{
    BCRYPT_KEY_HANDLE keyHandle = NULL;
    unsigned char* keyObject = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    NTSTATUS status;
    ULONG resultLength = 0;
    BOOL success = FALSE;

    if (!key || !nonce || !plaintext || !outCiphertext || !outTag)
    {
        return FALSE;
    }

    if (!GenerateSymmetricKey(
            g_hAesGcmAlgorithm,
            g_AesGcmObjectLength,
            key,
            QUIC_AEAD_KEY_LENGTH,
            &keyHandle,
            &keyObject))
    {
        return FALSE;
    }

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = QUIC_AEAD_IV_LENGTH;
    authInfo.pbAuthData = (PUCHAR)aad;
    authInfo.cbAuthData = aadLength;
    authInfo.pbTag = outTag;
    authInfo.cbTag = QUIC_AEAD_TAG_LENGTH;

    status = BCryptEncrypt(
        keyHandle,
        (PUCHAR)plaintext,
        plaintextLength,
        &authInfo,
        NULL,
        0,
        outCiphertext,
        plaintextLength,
        &resultLength,
        0);
    if (!NT_SUCCESS(status) || resultLength != plaintextLength)
    {
        LogMessage("[!] BCryptEncrypt(AES-GCM) failed: 0x%08lx", (unsigned long)status);
        goto Cleanup;
    }

    success = TRUE;

Cleanup:
    if (keyHandle)
    {
        BCryptDestroyKey(keyHandle);
    }

    if (keyObject)
    {
        free(keyObject);
    }

    return success;
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

static void ResetHookSlot(UDP_HOOK_SLOT* slot)
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

static BOOL InstallInlineHook(
    UDP_HOOK_SLOT* slot,
    void* target,
    void* detour,
    void** originalStorage)
{
    DWORD oldProtect;
    unsigned char* trampoline;
    SIZE_T patchLength;
    SIZE_T trampolineSize;

    if (!slot || !target || !detour || !originalStorage)
    {
        return FALSE;
    }

    patchLength = slot->config ? slot->config->patchLength : 0;
    if (patchLength < JUMP_SIZE || patchLength > sizeof(slot->originalBytes))
    {
        LogMessage("[!] Invalid UDP hook patch length for %s", slot->config ? slot->config->label : "unknown");
        return FALSE;
    }

    trampolineSize = patchLength + JUMP_SIZE;

    memcpy(slot->originalBytes, target, patchLength);
    slot->target = (unsigned char*)target;

    trampoline = (unsigned char*)VirtualAlloc(
        NULL,
        trampolineSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!trampoline)
    {
        LogMessage("[!] VirtualAlloc for UDP hook trampoline failed: %lu", GetLastError());
        return FALSE;
    }

    memcpy(trampoline, slot->originalBytes, patchLength);
    WriteJumpInstruction(trampoline + patchLength, slot->target + patchLength);

    if (!VirtualProtect(target, patchLength, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        LogMessage("[!] VirtualProtect for UDP hook failed: %lu", GetLastError());
        VirtualFree(trampoline, 0, MEM_RELEASE);
        return FALSE;
    }

    WriteJumpInstruction((unsigned char*)target, detour);
    if (patchLength > JUMP_SIZE)
    {
        memset((unsigned char*)target + JUMP_SIZE, 0x90, patchLength - JUMP_SIZE);
    }

    VirtualProtect(target, patchLength, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), target, patchLength);
    FlushInstructionCache(GetCurrentProcess(), trampoline, trampolineSize);

    slot->trampoline = trampoline;
    slot->installed = TRUE;
    *originalStorage = trampoline;
    return TRUE;
}

static void ResetIatHookSlot(IAT_HOOK_SLOT* slot)
{
    if (!slot)
    {
        return;
    }

    slot->iatEntry = NULL;
    slot->originalValue = 0;
    slot->installed = FALSE;
}

static BOOL ValidatePeImageForIatHooks(HMODULE module)
{
    const unsigned char* moduleBytes;
    const IMAGE_DOS_HEADER* dosHeader;
    const IMAGE_NT_HEADERS* ntHeaders;

    if (!module)
    {
        return FALSE;
    }

    moduleBytes = (const unsigned char*)module;
    dosHeader = (const IMAGE_DOS_HEADER*)moduleBytes;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        LogMessage("[!] Invalid DOS header while preparing IAT hooks");
        return FALSE;
    }

    ntHeaders = (const IMAGE_NT_HEADERS*)(moduleBytes + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        LogMessage("[!] Invalid NT header while preparing IAT hooks");
        return FALSE;
    }

    if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT ||
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
    {
        LogMessage("[!] Host module has no import directory for IAT hooks");
        return FALSE;
    }

    return TRUE;
}

static BOOL InstallIatHooks(HMODULE module, DWORD* outInstalledCount)
{
    DWORD hookIndex;
    DWORD installedCount = 0;

    if (outInstalledCount)
    {
        *outInstalledCount = 0;
    }

    if (!ValidatePeImageForIatHooks(module))
    {
        return FALSE;
    }

    for (hookIndex = 0;
         hookIndex < sizeof(g_IatHookSlots) / sizeof(g_IatHookSlots[0]);
         ++hookIndex)
    {
        IAT_HOOK_SLOT* slot = &g_IatHookSlots[hookIndex];

        slot->config = &g_IatHookConfigs[hookIndex];
        ResetIatHookSlot(slot);
        slot->config = &g_IatHookConfigs[hookIndex];

        if (InstallSingleIatHook(module, slot))
        {
            installedCount++;
        }
    }

    if (outInstalledCount)
    {
        *outInstalledCount = installedCount;
    }

    return TRUE;
}

static BOOL InstallSingleIatHook(HMODULE module, IAT_HOOK_SLOT* slot)
{
    const unsigned char* moduleBytes;
    const IMAGE_DOS_HEADER* dosHeader;
    const IMAGE_NT_HEADERS* ntHeaders;
    const IMAGE_IMPORT_DESCRIPTOR* importDescriptor;
    const IMAGE_IMPORT_DESCRIPTOR* matchedDescriptor = NULL;
    IMAGE_THUNK_DATA* firstThunk;
    IMAGE_THUNK_DATA* originalFirstThunk;
    FARPROC expectedImport = NULL;
    DWORD thunkIndex;
    DWORD oldProtect;

    if (!module || !slot || !slot->config)
    {
        return FALSE;
    }

    moduleBytes = (const unsigned char*)module;
    dosHeader = (const IMAGE_DOS_HEADER*)moduleBytes;
    ntHeaders = (const IMAGE_NT_HEADERS*)(moduleBytes + dosHeader->e_lfanew);
    importDescriptor = (const IMAGE_IMPORT_DESCRIPTOR*)(
        moduleBytes +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; importDescriptor->Name != 0; ++importDescriptor)
    {
        const char* importedModuleName = (const char*)(moduleBytes + importDescriptor->Name);

        if (StringEqualsInsensitive(importedModuleName, slot->config->importModule))
        {
            matchedDescriptor = importDescriptor;
            break;
        }
    }

    if (!matchedDescriptor)
    {
        LogMessage(
            slot->config->optional
                ? "[*] Host module does not import optional Winsock API: %s"
                : "[!] Host module does not import required Winsock API: %s",
            slot->config->label);
        return FALSE;
    }

    if (g_hWs2Module)
    {
        expectedImport = GetProcAddress(g_hWs2Module, slot->config->importName);
    }

    firstThunk = (IMAGE_THUNK_DATA*)(moduleBytes + matchedDescriptor->FirstThunk);
    originalFirstThunk = matchedDescriptor->OriginalFirstThunk != 0
                             ? (IMAGE_THUNK_DATA*)(moduleBytes + matchedDescriptor->OriginalFirstThunk)
                             : NULL;

    for (thunkIndex = 0; firstThunk[thunkIndex].u1.Function != 0; ++thunkIndex)
    {
        BOOL matched = FALSE;

        if (originalFirstThunk)
        {
            if (!IMAGE_SNAP_BY_ORDINAL(originalFirstThunk[thunkIndex].u1.Ordinal))
            {
                const IMAGE_IMPORT_BY_NAME* importByName = (const IMAGE_IMPORT_BY_NAME*)(
                    moduleBytes + originalFirstThunk[thunkIndex].u1.AddressOfData);

                matched = StringEqualsInsensitive(
                    (const char*)importByName->Name,
                    slot->config->importName);
            }
        }
        else if (expectedImport)
        {
            matched = firstThunk[thunkIndex].u1.Function == (ULONG_PTR)expectedImport;
        }

        if (!matched)
        {
            continue;
        }

        if (firstThunk[thunkIndex].u1.Function == (ULONG_PTR)slot->config->detour)
        {
            LogMessage("[*] IAT hook already active for %s", slot->config->label);
            return FALSE;
        }

        if (!VirtualProtect(
                &firstThunk[thunkIndex].u1.Function,
                sizeof(firstThunk[thunkIndex].u1.Function),
                PAGE_READWRITE,
                &oldProtect))
        {
            LogMessage(
                "[!] VirtualProtect failed while patching IAT entry for %s: %lu",
                slot->config->label,
                GetLastError());
            return FALSE;
        }

        slot->iatEntry = (ULONG_PTR*)&firstThunk[thunkIndex].u1.Function;
        slot->originalValue = firstThunk[thunkIndex].u1.Function;
        firstThunk[thunkIndex].u1.Function = (ULONG_PTR)slot->config->detour;
        VirtualProtect(
            &firstThunk[thunkIndex].u1.Function,
            sizeof(firstThunk[thunkIndex].u1.Function),
            oldProtect,
            &oldProtect);

        if (slot->config->originalStorage)
        {
            *slot->config->originalStorage = (void*)slot->originalValue;
        }

        slot->installed = TRUE;
        LogMessage(
            "[+] Patched IAT entry for %s at %p -> %p",
            slot->config->label,
            slot->iatEntry,
            slot->config->detour);
        return TRUE;
    }

    LogMessage(
        slot->config->optional
            ? "[*] Optional IAT entry not found for %s"
            : "[!] IAT entry not found for %s",
        slot->config->label);
    return FALSE;
}

static BOOL StringEqualsInsensitive(const char* left, const char* right)
{
    return left && right && _stricmp(left, right) == 0;
}

static BOOL IsSupportedVersion(DWORD version)
{
    return version == QUIC_VERSION_1 || version == QUIC_VERSION_2;
}

static BOOL IsInitialPacketType(DWORD version, unsigned char firstByte)
{
    unsigned char packetType = firstByte & QUIC_LONG_PACKET_TYPE_MASK;

    if (version == QUIC_VERSION_1)
    {
        return packetType == QUIC_PACKET_TYPE_INITIAL_V1;
    }

    if (version == QUIC_VERSION_2)
    {
        return packetType == QUIC_PACKET_TYPE_INITIAL_V2;
    }

    return FALSE;
}

static BOOL IsRetryPacketType(DWORD version, unsigned char firstByte)
{
    unsigned char packetType = firstByte & QUIC_LONG_PACKET_TYPE_MASK;

    if (version == QUIC_VERSION_1)
    {
        return packetType == QUIC_PACKET_TYPE_RETRY_V1;
    }

    if (version == QUIC_VERSION_2)
    {
        return packetType == QUIC_PACKET_TYPE_RETRY_V2;
    }

    return FALSE;
}

static BOOL TryParseProtectedInitialPacket(
    const unsigned char* packet,
    SIZE_T packetLength,
    QUIC_PACKET_METADATA* metadata,
    const UDP_TRACE_CONTEXT* traceContext)
{
    SIZE_T cursor;
    ULONGLONG tokenLength;
    ULONGLONG payloadLength;
    SIZE_T encodedLength;
    SIZE_T tokenBytes;
    SIZE_T payloadBytes;

    if (!packet || !metadata || packetLength < 7)
    {
        return FALSE;
    }

    memset(metadata, 0, sizeof(*metadata));

    if ((packet[0] & QUIC_HEADER_FORM_LONG) == 0)
    {
        LogPassthroughSample(
            &g_ShortHeaderPassthroughCount,
            "short-header UDP packet",
            traceContext);
        return FALSE;
    }

    if ((packet[0] & QUIC_FIXED_BIT) == 0)
    {
        LogPassthroughSample(
            &g_ParseFailureCount,
            "long-header packet missing fixed bit",
            traceContext);
        return FALSE;
    }

    metadata->version = ReadUInt32BE(packet + 1);
    if (!IsSupportedVersion(metadata->version))
    {
        LogPassthroughSample(
            &g_UnsupportedVersionPassthroughCount,
            "unsupported QUIC version",
            traceContext);
        return FALSE;
    }

    if (IsRetryPacketType(metadata->version, packet[0]))
    {
        LogPassthroughSample(&g_RetryPassthroughCount, "Retry packet", traceContext);
        return FALSE;
    }

    if (!IsInitialPacketType(metadata->version, packet[0]))
    {
        LogPassthroughSample(
            &g_NonInitialPassthroughCount,
            "non-Initial long-header packet",
            traceContext);
        return FALSE;
    }

    cursor = 5;
    metadata->dcidLength = packet[cursor++];
    if (metadata->dcidLength > QUIC_MAX_CONNECTION_ID_LENGTH ||
        cursor + metadata->dcidLength >= packetLength)
    {
        LogPassthroughSample(&g_ParseFailureCount, "invalid QUIC DCID", traceContext);
        return FALSE;
    }

    memcpy(metadata->dcid, packet + cursor, metadata->dcidLength);
    cursor += metadata->dcidLength;

    metadata->scidLength = packet[cursor++];
    if (metadata->scidLength > QUIC_MAX_CONNECTION_ID_LENGTH ||
        cursor + metadata->scidLength > packetLength)
    {
        LogPassthroughSample(&g_ParseFailureCount, "invalid QUIC SCID", traceContext);
        return FALSE;
    }

    cursor += metadata->scidLength;

    if (!TryReadVarInt(packet + cursor, packetLength - cursor, &tokenLength, &encodedLength))
    {
        LogPassthroughSample(
            &g_ParseFailureCount,
            "truncated QUIC token length",
            traceContext);
        return FALSE;
    }

    cursor += encodedLength;
    if (!UInt64ToSize(tokenLength, &tokenBytes) || cursor + tokenBytes > packetLength)
    {
        LogPassthroughSample(&g_ParseFailureCount, "invalid QUIC token", traceContext);
        return FALSE;
    }

    cursor += tokenBytes;

    if (!TryReadVarInt(packet + cursor, packetLength - cursor, &payloadLength, &encodedLength))
    {
        LogPassthroughSample(
            &g_ParseFailureCount,
            "truncated QUIC payload length",
            traceContext);
        return FALSE;
    }

    metadata->pnOffset = cursor + encodedLength;
    if (metadata->pnOffset + 4 + QUIC_HP_SAMPLE_LENGTH > packetLength)
    {
        LogPassthroughSample(
            &g_ParseFailureCount,
            "packet too short for QUIC header protection sample",
            traceContext);
        return FALSE;
    }

    if (!UInt64ToSize(payloadLength, &payloadBytes))
    {
        LogPassthroughSample(
            &g_ParseFailureCount,
            "QUIC payload length overflow",
            traceContext);
        return FALSE;
    }

    metadata->packetLength = metadata->pnOffset + payloadBytes;
    if (metadata->packetLength > packetLength)
    {
        LogPassthroughSample(
            &g_ParseFailureCount,
            "truncated QUIC datagram",
            traceContext);
        return FALSE;
    }

    return TRUE;
}

static BOOL RemoveHeaderProtection(
    unsigned char* packet,
    const QUIC_INITIAL_KEYS* keys,
    QUIC_PACKET_METADATA* metadata)
{
    unsigned char mask[QUIC_HP_SAMPLE_LENGTH];
    SIZE_T sampleOffset;
    SIZE_T packetNumberIndex;
    SIZE_T ciphertextLength;

    if (!packet || !keys || !metadata)
    {
        return FALSE;
    }

    sampleOffset = metadata->pnOffset + 4;
    if (sampleOffset + QUIC_HP_SAMPLE_LENGTH > metadata->packetLength)
    {
        return FALSE;
    }

    if (!ComputeHeaderProtectionMask(
            keys->hpKey,
            packet + sampleOffset,
            mask,
            sizeof(mask)))
    {
        return FALSE;
    }

    metadata->unprotectedFirstByte = packet[0] ^ (mask[0] & 0x0f);
    metadata->packetNumberLength = (unsigned char)((metadata->unprotectedFirstByte & 0x03) + 1);
    if (metadata->pnOffset + metadata->packetNumberLength > metadata->packetLength)
    {
        return FALSE;
    }

    packet[0] = metadata->unprotectedFirstByte;
    metadata->packetNumber = 0;
    for (packetNumberIndex = 0;
         packetNumberIndex < metadata->packetNumberLength;
         ++packetNumberIndex)
    {
        metadata->packetNumberBytes[packetNumberIndex] =
            packet[metadata->pnOffset + packetNumberIndex] ^ mask[packetNumberIndex + 1];
        packet[metadata->pnOffset + packetNumberIndex] = metadata->packetNumberBytes[packetNumberIndex];
        metadata->packetNumber = (metadata->packetNumber << 8) | metadata->packetNumberBytes[packetNumberIndex];
    }

    metadata->headerLength = metadata->pnOffset + metadata->packetNumberLength;
    metadata->ciphertextOffset = metadata->headerLength;
    ciphertextLength = metadata->packetLength - metadata->ciphertextOffset;
    if (ciphertextLength < QUIC_AEAD_TAG_LENGTH)
    {
        return FALSE;
    }

    metadata->ciphertextLengthWithTag = ciphertextLength;
    metadata->plaintextLength = ciphertextLength - QUIC_AEAD_TAG_LENGTH;
    return TRUE;
}

static void ApplyHeaderProtection(
    unsigned char* packet,
    const QUIC_INITIAL_KEYS* keys,
    const QUIC_PACKET_METADATA* metadata)
{
    unsigned char mask[QUIC_HP_SAMPLE_LENGTH];
    SIZE_T sampleOffset;
    SIZE_T packetNumberIndex;

    if (!packet || !keys || !metadata)
    {
        return;
    }

    sampleOffset = metadata->pnOffset + 4;
    if (sampleOffset + QUIC_HP_SAMPLE_LENGTH > metadata->packetLength)
    {
        return;
    }

    if (!ComputeHeaderProtectionMask(
            keys->hpKey,
            packet + sampleOffset,
            mask,
            sizeof(mask)))
    {
        return;
    }

    packet[0] = metadata->unprotectedFirstByte ^ (mask[0] & 0x0f);
    for (packetNumberIndex = 0;
         packetNumberIndex < metadata->packetNumberLength;
         ++packetNumberIndex)
    {
        packet[metadata->pnOffset + packetNumberIndex] =
            metadata->packetNumberBytes[packetNumberIndex] ^ mask[packetNumberIndex + 1];
    }
}

static BOOL TryParseAckFrame(
    const unsigned char* payload,
    SIZE_T payloadLength,
    SIZE_T* cursor,
    BOOL withEcn)
{
    ULONGLONG ackRangeCount;
    ULONGLONG index;

    if (!TryConsumeVarInt(payload, payloadLength, cursor, NULL) ||
        !TryConsumeVarInt(payload, payloadLength, cursor, NULL) ||
        !TryConsumeVarInt(payload, payloadLength, cursor, &ackRangeCount) ||
        !TryConsumeVarInt(payload, payloadLength, cursor, NULL))
    {
        return FALSE;
    }

    for (index = 0; index < ackRangeCount; ++index)
    {
        if (!TryConsumeVarInt(payload, payloadLength, cursor, NULL) ||
            !TryConsumeVarInt(payload, payloadLength, cursor, NULL))
        {
            return FALSE;
        }
    }

    if (withEcn)
    {
        if (!TryConsumeVarInt(payload, payloadLength, cursor, NULL) ||
            !TryConsumeVarInt(payload, payloadLength, cursor, NULL) ||
            !TryConsumeVarInt(payload, payloadLength, cursor, NULL))
        {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOL TryParseQuicFrame(
    const unsigned char* payload,
    SIZE_T payloadLength,
    SIZE_T frameOffset,
    QUIC_FRAME_SLICE* frame)
{
    SIZE_T cursor;
    SIZE_T encodedLength;
    ULONGLONG value;
    SIZE_T bytesLength;
    unsigned char frameTypeByte;

    if (!payload || !frame || frameOffset >= payloadLength)
    {
        return FALSE;
    }

    memset(frame, 0, sizeof(*frame));
    frame->offset = frameOffset;

    frameTypeByte = payload[frameOffset];
    if (frameTypeByte == QUIC_PADDING_FRAME_TYPE)
    {
        frame->type = QUIC_PADDING_FRAME_TYPE;
        frame->length = 1;
        return TRUE;
    }

    if (!TryReadVarInt(payload + frameOffset, payloadLength - frameOffset, &frame->type, &encodedLength))
    {
        return FALSE;
    }

    cursor = frameOffset + encodedLength;

    switch ((unsigned int)frame->type)
    {
    case 0x01:
    case 0x1e:
        break;

    case 0x02:
        if (!TryParseAckFrame(payload, payloadLength, &cursor, FALSE))
        {
            return FALSE;
        }
        break;

    case 0x03:
        if (!TryParseAckFrame(payload, payloadLength, &cursor, TRUE))
        {
            return FALSE;
        }
        break;

    case 0x04:
        if (!TryConsumeVarInt(payload, payloadLength, &cursor, NULL) ||
            !TryConsumeVarInt(payload, payloadLength, &cursor, NULL) ||
            !TryConsumeVarInt(payload, payloadLength, &cursor, NULL))
        {
            return FALSE;
        }
        break;

    case 0x05:
        if (!TryConsumeVarInt(payload, payloadLength, &cursor, NULL) ||
            !TryConsumeVarInt(payload, payloadLength, &cursor, NULL))
        {
            return FALSE;
        }
        break;

    case QUIC_CRYPTO_FRAME_TYPE:
        frame->isCrypto = TRUE;
        if (!TryConsumeVarInt(payload, payloadLength, &cursor, &frame->cryptoOffset))
        {
            return FALSE;
        }

        frame->cryptoLengthFieldOffset = cursor;
        if (!TryReadVarInt(payload + cursor, payloadLength - cursor, &value, &encodedLength))
        {
            return FALSE;
        }

        frame->cryptoLengthFieldLength = encodedLength;
        cursor += encodedLength;
        frame->cryptoDataOffset = cursor;

        if (!UInt64ToSize(value, &bytesLength) ||
            !TryConsumeBytes(payloadLength, &cursor, bytesLength))
        {
            return FALSE;
        }

        frame->cryptoDataLength = bytesLength;
        break;

    case 0x07:
        if (!TryConsumeVarInt(payload, payloadLength, &cursor, &value) ||
            !UInt64ToSize(value, &bytesLength) ||
            !TryConsumeBytes(payloadLength, &cursor, bytesLength))
        {
            return FALSE;
        }
        break;

    case 0x10:
    case 0x12:
    case 0x13:
    case 0x14:
    case 0x16:
    case 0x17:
    case 0x19:
        if (!TryConsumeVarInt(payload, payloadLength, &cursor, NULL))
        {
            return FALSE;
        }
        break;

    case 0x11:
    case 0x15:
        if (!TryConsumeVarInt(payload, payloadLength, &cursor, NULL) ||
            !TryConsumeVarInt(payload, payloadLength, &cursor, NULL))
        {
            return FALSE;
        }
        break;

    case 0x18:
        if (!TryConsumeVarInt(payload, payloadLength, &cursor, NULL) ||
            !TryConsumeVarInt(payload, payloadLength, &cursor, NULL))
        {
            return FALSE;
        }

        if (!TryConsumeBytes(payloadLength, &cursor, 1))
        {
            return FALSE;
        }

        bytesLength = payload[cursor - 1];
        if (bytesLength == 0 || bytesLength > QUIC_MAX_CONNECTION_ID_LENGTH ||
            !TryConsumeBytes(payloadLength, &cursor, bytesLength + 16))
        {
            return FALSE;
        }
        break;

    case 0x1a:
    case 0x1b:
        if (!TryConsumeBytes(payloadLength, &cursor, 8))
        {
            return FALSE;
        }
        break;

    case 0x1c:
        if (!TryConsumeVarInt(payload, payloadLength, &cursor, NULL) ||
            !TryConsumeVarInt(payload, payloadLength, &cursor, NULL) ||
            !TryConsumeVarInt(payload, payloadLength, &cursor, &value) ||
            !UInt64ToSize(value, &bytesLength) ||
            !TryConsumeBytes(payloadLength, &cursor, bytesLength))
        {
            return FALSE;
        }
        break;

    case 0x1d:
        if (!TryConsumeVarInt(payload, payloadLength, &cursor, NULL) ||
            !TryConsumeVarInt(payload, payloadLength, &cursor, &value) ||
            !UInt64ToSize(value, &bytesLength) ||
            !TryConsumeBytes(payloadLength, &cursor, bytesLength))
        {
            return FALSE;
        }
        break;

    default:
        if (frame->type >= 0x08 && frame->type <= 0x0f)
        {
            BOOL hasOffset = (frame->type & 0x04) != 0;
            BOOL hasLength = (frame->type & 0x02) != 0;

            if (!TryConsumeVarInt(payload, payloadLength, &cursor, NULL))
            {
                return FALSE;
            }

            if (hasOffset && !TryConsumeVarInt(payload, payloadLength, &cursor, NULL))
            {
                return FALSE;
            }

            if (hasLength)
            {
                if (!TryConsumeVarInt(payload, payloadLength, &cursor, &value) ||
                    !UInt64ToSize(value, &bytesLength) ||
                    !TryConsumeBytes(payloadLength, &cursor, bytesLength))
                {
                    return FALSE;
                }
            }
            else
            {
                cursor = payloadLength;
            }
        }
        else if (frame->type == QUIC_DATAGRAM_FRAME_TYPE ||
                 frame->type == (QUIC_DATAGRAM_FRAME_TYPE + 1))
        {
            BOOL hasLength = (frame->type & 0x01) != 0;

            if (hasLength)
            {
                if (!TryConsumeVarInt(payload, payloadLength, &cursor, &value) ||
                    !UInt64ToSize(value, &bytesLength) ||
                    !TryConsumeBytes(payloadLength, &cursor, bytesLength))
                {
                    return FALSE;
                }
            }
            else
            {
                cursor = payloadLength;
            }
        }
        else
        {
            return FALSE;
        }
        break;
    }

    if (cursor < frameOffset || cursor > payloadLength)
    {
        return FALSE;
    }

    frame->length = cursor - frameOffset;
    return frame->length > 0;
}

static void FreeQuicCryptoRun(QUIC_CRYPTO_RUN* run)
{
    if (!run)
    {
        return;
    }

    if (run->includedCryptoFrames)
    {
        free(run->includedCryptoFrames);
    }

    if (run->frames)
    {
        free(run->frames);
    }

    memset(run, 0, sizeof(*run));
    run->replacementFrameIndex = (SIZE_T)-1;
}

static BOOL TryCollectCryptoRun(
    const unsigned char* payload,
    SIZE_T payloadLength,
    QUIC_CRYPTO_RUN* run)
{
    QUIC_FRAME_SLICE* frames = NULL;
    BOOL* includedCryptoFrames = NULL;
    SIZE_T frameCapacity;
    SIZE_T frameCount = 0;
    SIZE_T cursor = 0;
    SIZE_T index;
    BOOL foundAnyCrypto = FALSE;
    ULONGLONG startOffset = 0;

    if (!payload || !run || payloadLength == 0)
    {
        return FALSE;
    }

    memset(run, 0, sizeof(*run));
    run->replacementFrameIndex = (SIZE_T)-1;

    frameCapacity = payloadLength;
    frames = (QUIC_FRAME_SLICE*)malloc(sizeof(*frames) * frameCapacity);
    if (!frames)
    {
        return FALSE;
    }

    while (cursor < payloadLength)
    {
        if (payload[cursor] == QUIC_PADDING_FRAME_TYPE)
        {
            SIZE_T paddingStart = cursor;

            while (cursor < payloadLength && payload[cursor] == QUIC_PADDING_FRAME_TYPE)
            {
                cursor++;
            }

            run->paddingByteCount += cursor - paddingStart;
            continue;
        }

        if (frameCount >= frameCapacity ||
            !TryParseQuicFrame(payload, payloadLength, cursor, &frames[frameCount]))
        {
            goto Cleanup;
        }

        cursor += frames[frameCount].length;
        frameCount++;
    }

    for (index = 0; index < frameCount; ++index)
    {
        const QUIC_FRAME_SLICE* frame = &frames[index];

        if (!frame->isCrypto || frame->cryptoDataLength == 0)
        {
            continue;
        }

        if (!foundAnyCrypto || frame->cryptoOffset < startOffset)
        {
            startOffset = frame->cryptoOffset;
            foundAnyCrypto = TRUE;
        }
    }

    if (!foundAnyCrypto)
    {
        goto Cleanup;
    }

    includedCryptoFrames = (BOOL*)calloc(frameCount, sizeof(*includedCryptoFrames));
    if (!includedCryptoFrames)
    {
        goto Cleanup;
    }

    run->startOffset = startOffset;
    run->frameCount = frameCount;

    for (;;)
    {
        BOOL foundNextCryptoFrame = FALSE;
        ULONGLONG expectedOffset;

        if (run->contiguousCryptoLength > (SIZE_T)(ULLONG_MAX - run->startOffset))
        {
            goto Cleanup;
        }

        expectedOffset = run->startOffset + run->contiguousCryptoLength;

        for (index = 0; index < frameCount; ++index)
        {
            const QUIC_FRAME_SLICE* frame = &frames[index];

            if (!frame->isCrypto ||
                includedCryptoFrames[index] ||
                frame->cryptoDataLength == 0 ||
                frame->cryptoOffset != expectedOffset)
            {
                continue;
            }

            if (run->contiguousCryptoLength > ((SIZE_T)-1) - frame->cryptoDataLength ||
                run->consumedCryptoFrameBytes > ((SIZE_T)-1) - frame->length)
            {
                goto Cleanup;
            }

            includedCryptoFrames[index] = TRUE;
            run->contiguousCryptoLength += frame->cryptoDataLength;
            run->consumedCryptoFrameBytes += frame->length;
            if (run->replacementFrameIndex == (SIZE_T)-1 || index < run->replacementFrameIndex)
            {
                run->replacementFrameIndex = index;
            }

            foundNextCryptoFrame = TRUE;
            break;
        }

        if (!foundNextCryptoFrame)
        {
            break;
        }
    }

    if (run->replacementFrameIndex == (SIZE_T)-1 ||
        run->contiguousCryptoLength == 0)
    {
        goto Cleanup;
    }

    run->frames = frames;
    run->includedCryptoFrames = includedCryptoFrames;
    return TRUE;

Cleanup:
    if (includedCryptoFrames)
    {
        free(includedCryptoFrames);
    }

    if (frames)
    {
        free(frames);
    }

    memset(run, 0, sizeof(*run));
    run->replacementFrameIndex = (SIZE_T)-1;
    return FALSE;
}

static unsigned char* CopyCryptoRunBytes(
    const unsigned char* payload,
    const QUIC_CRYPTO_RUN* run)
{
    unsigned char* crypto = NULL;
    SIZE_T cursor = 0;
    ULONGLONG expectedOffset;

    if (!payload || !run || run->contiguousCryptoLength == 0)
    {
        return NULL;
    }

    crypto = (unsigned char*)malloc(run->contiguousCryptoLength);
    if (!crypto)
    {
        return NULL;
    }

    expectedOffset = run->startOffset;
    while (cursor < run->contiguousCryptoLength)
    {
        SIZE_T index;
        BOOL copiedFrame = FALSE;

        for (index = 0; index < run->frameCount; ++index)
        {
            const QUIC_FRAME_SLICE* frame = &run->frames[index];

            if (!run->includedCryptoFrames[index] ||
                frame->cryptoOffset != expectedOffset)
            {
                continue;
            }

            memcpy(
                crypto + cursor,
                payload + frame->cryptoDataOffset,
                frame->cryptoDataLength);
            cursor += frame->cryptoDataLength;
            expectedOffset += frame->cryptoDataLength;
            copiedFrame = TRUE;
            break;
        }

        if (!copiedFrame)
        {
            free(crypto);
            return NULL;
        }
    }

    return crypto;
}

static BOOL BuildRewrittenPayloadFromCryptoRun(
    const unsigned char* payload,
    SIZE_T payloadLength,
    const QUIC_CRYPTO_RUN* run,
    ULONGLONG replacementOffset,
    const unsigned char* replacementCrypto,
    SIZE_T replacementCryptoLength,
    unsigned char** outRewrittenPayload)
{
    unsigned char newCryptoFrameHeader[1 + (2 * QUIC_MAX_VARINT_LENGTH)];
    SIZE_T newCryptoFrameHeaderSize = 0;
    SIZE_T encodedSize;
    LONGLONG delta;
    SIZE_T rebuiltPaddingCount;
    unsigned char* rebuiltPayload = NULL;
    SIZE_T rebuiltOffset = 0;
    SIZE_T index;

    if (!payload ||
        !run ||
        !outRewrittenPayload ||
        run->replacementFrameIndex == (SIZE_T)-1 ||
        replacementCryptoLength == 0 ||
        !replacementCrypto)
    {
        return FALSE;
    }

    *outRewrittenPayload = NULL;

    newCryptoFrameHeader[0] = QUIC_CRYPTO_FRAME_TYPE;
    newCryptoFrameHeaderSize = 1;

    encodedSize = EncodeVarInt(
        replacementOffset,
        newCryptoFrameHeader + newCryptoFrameHeaderSize,
        sizeof(newCryptoFrameHeader) - newCryptoFrameHeaderSize);
    if (encodedSize == 0)
    {
        return FALSE;
    }
    newCryptoFrameHeaderSize += encodedSize;

    encodedSize = EncodeVarInt(
        (ULONGLONG)replacementCryptoLength,
        newCryptoFrameHeader + newCryptoFrameHeaderSize,
        sizeof(newCryptoFrameHeader) - newCryptoFrameHeaderSize);
    if (encodedSize == 0)
    {
        return FALSE;
    }
    newCryptoFrameHeaderSize += encodedSize;

    delta =
        (LONGLONG)newCryptoFrameHeaderSize +
        (LONGLONG)replacementCryptoLength -
        (LONGLONG)run->consumedCryptoFrameBytes;
    if (delta > (LONGLONG)run->paddingByteCount)
    {
        return FALSE;
    }

    if (delta >= 0)
    {
        rebuiltPaddingCount = run->paddingByteCount - (SIZE_T)delta;
    }
    else
    {
        SIZE_T reclaimedBytes = (SIZE_T)(-delta);

        if (run->paddingByteCount > ((SIZE_T)-1) - reclaimedBytes)
        {
            return FALSE;
        }

        rebuiltPaddingCount = run->paddingByteCount + reclaimedBytes;
    }

    rebuiltPayload = (unsigned char*)malloc(payloadLength);
    if (!rebuiltPayload)
    {
        return FALSE;
    }

    for (index = 0; index < run->frameCount; ++index)
    {
        if (run->includedCryptoFrames[index])
        {
            if (index != run->replacementFrameIndex)
            {
                continue;
            }

            if (newCryptoFrameHeaderSize > payloadLength - rebuiltOffset ||
                replacementCryptoLength > payloadLength - rebuiltOffset - newCryptoFrameHeaderSize)
            {
                free(rebuiltPayload);
                return FALSE;
            }

            memcpy(
                rebuiltPayload + rebuiltOffset,
                newCryptoFrameHeader,
                newCryptoFrameHeaderSize);
            rebuiltOffset += newCryptoFrameHeaderSize;

            memcpy(
                rebuiltPayload + rebuiltOffset,
                replacementCrypto,
                replacementCryptoLength);
            rebuiltOffset += replacementCryptoLength;
            continue;
        }

        if (run->frames[index].length > payloadLength - rebuiltOffset)
        {
            free(rebuiltPayload);
            return FALSE;
        }

        memcpy(
            rebuiltPayload + rebuiltOffset,
            payload + run->frames[index].offset,
            run->frames[index].length);
        rebuiltOffset += run->frames[index].length;
    }

    if (rebuiltPaddingCount > payloadLength - rebuiltOffset)
    {
        free(rebuiltPayload);
        return FALSE;
    }

    memset(rebuiltPayload + rebuiltOffset, 0, rebuiltPaddingCount);
    rebuiltOffset += rebuiltPaddingCount;

    if (rebuiltOffset != payloadLength)
    {
        free(rebuiltPayload);
        return FALSE;
    }

    *outRewrittenPayload = rebuiltPayload;
    return TRUE;
}

static void FreePreparedInitialPacket(PREPARED_INITIAL_PACKET* prepared)
{
    if (!prepared)
    {
        return;
    }

    FreeQuicCryptoRun(&prepared->cryptoRun);

    if (prepared->plaintext)
    {
        free(prepared->plaintext);
    }

    if (prepared->datagram)
    {
        free(prepared->datagram);
    }

    memset(prepared, 0, sizeof(*prepared));
}

static BOOL TryPrepareInitialPacket(
    const unsigned char* datagram,
    SIZE_T datagramLength,
    const UDP_TRACE_CONTEXT* traceContext,
    PREPARED_INITIAL_PACKET* prepared)
{
    if (!datagram || datagramLength == 0 || !prepared)
    {
        return FALSE;
    }

    memset(prepared, 0, sizeof(*prepared));
    prepared->cryptoRun.replacementFrameIndex = (SIZE_T)-1;

    prepared->datagram = (unsigned char*)malloc(datagramLength);
    if (!prepared->datagram)
    {
        return FALSE;
    }

    memcpy(prepared->datagram, datagram, datagramLength);
    prepared->datagramLength = datagramLength;

    if (!TryParseProtectedInitialPacket(
            prepared->datagram,
            datagramLength,
            &prepared->metadata,
            traceContext))
    {
        goto Cleanup;
    }

    if (!DeriveClientInitialKeys(
            prepared->metadata.version,
            prepared->metadata.dcid,
            prepared->metadata.dcidLength,
            &prepared->keys))
    {
        goto Cleanup;
    }

    if (!RemoveHeaderProtection(prepared->datagram, &prepared->keys, &prepared->metadata))
    {
        goto Cleanup;
    }

    BuildPacketNonce(prepared->keys.packetIv, prepared->metadata.packetNumber, prepared->nonce);

    prepared->plaintext = (unsigned char*)malloc(prepared->metadata.plaintextLength);
    if (!prepared->plaintext)
    {
        goto Cleanup;
    }

    if (!DecryptAes128Gcm(
            prepared->keys.packetKey,
            prepared->nonce,
            prepared->datagram,
            (ULONG)prepared->metadata.headerLength,
            prepared->datagram + prepared->metadata.ciphertextOffset,
            (ULONG)prepared->metadata.plaintextLength,
            prepared->datagram + prepared->metadata.ciphertextOffset + prepared->metadata.plaintextLength,
            prepared->plaintext))
    {
        goto Cleanup;
    }

    if (!TryCollectCryptoRun(
            prepared->plaintext,
            prepared->metadata.plaintextLength,
            &prepared->cryptoRun))
    {
        goto Cleanup;
    }

    return TRUE;

Cleanup:
    FreePreparedInitialPacket(prepared);
    return FALSE;
}

static BOOL ApplyRewrittenPayloadToPreparedInitial(
    PREPARED_INITIAL_PACKET* prepared,
    const unsigned char* rewrittenPayload)
{
    if (!prepared || !prepared->datagram || !rewrittenPayload)
    {
        return FALSE;
    }

    if (!EncryptAes128Gcm(
            prepared->keys.packetKey,
            prepared->nonce,
            prepared->datagram,
            (ULONG)prepared->metadata.headerLength,
            rewrittenPayload,
            (ULONG)prepared->metadata.plaintextLength,
            prepared->datagram + prepared->metadata.ciphertextOffset,
            prepared->datagram + prepared->metadata.ciphertextOffset + prepared->metadata.plaintextLength))
    {
        return FALSE;
    }

    ApplyHeaderProtection(prepared->datagram, &prepared->keys, &prepared->metadata);
    return TRUE;
}

static int SendDatagramWithOperation(
    const UDP_SEND_OPERATION* operation,
    const unsigned char* datagram,
    SIZE_T datagramLength,
    UDP_SEND_RESULT* outResult)
{
    int result = SOCKET_ERROR;
    DWORD bytesSent = 0;
    int lastError = 0;

    if (outResult)
    {
        memset(outResult, 0, sizeof(*outResult));
        outResult->result = SOCKET_ERROR;
    }

    if (!operation || !datagram)
    {
        WSASetLastError(WSAEFAULT);
        lastError = WSAGetLastError();
        goto Cleanup;
    }

    switch (operation->method)
    {
    case UDP_SEND_METHOD_SEND:
        if (!g_pfnOriginalSend || datagramLength > INT_MAX)
        {
            WSASetLastError(WSAEMSGSIZE);
            lastError = WSAGetLastError();
            goto Cleanup;
        }

        result = g_pfnOriginalSend(
            operation->socketHandle,
            (const char*)datagram,
            (int)datagramLength,
            (int)operation->flags);
        if (result != SOCKET_ERROR)
        {
            bytesSent = (DWORD)result;
        }
        break;

    case UDP_SEND_METHOD_WSASEND:
        if (!g_pfnOriginalWSASend || datagramLength > ULONG_MAX)
        {
            WSASetLastError(WSAEMSGSIZE);
            lastError = WSAGetLastError();
            goto Cleanup;
        }
        else
        {
            WSABUF buffer;

            buffer.buf = (CHAR*)datagram;
            buffer.len = (ULONG)datagramLength;
            result = g_pfnOriginalWSASend(
                operation->socketHandle,
                &buffer,
                1,
                &bytesSent,
                operation->flags,
                NULL,
                NULL);
        }
        break;

    case UDP_SEND_METHOD_WSASENDTO:
        if (!g_pfnOriginalWSASendTo ||
            datagramLength > ULONG_MAX ||
            operation->target.addressLength <= 0)
        {
            WSASetLastError(WSAEMSGSIZE);
            lastError = WSAGetLastError();
            goto Cleanup;
        }
        else
        {
            WSABUF buffer;

            buffer.buf = (CHAR*)datagram;
            buffer.len = (ULONG)datagramLength;
            result = g_pfnOriginalWSASendTo(
                operation->socketHandle,
                &buffer,
                1,
                &bytesSent,
                operation->flags,
                (const struct sockaddr*)&operation->target.address,
                operation->target.addressLength,
                NULL,
                NULL);
        }
        break;

    case UDP_SEND_METHOD_WSASENDMSG:
        if (!g_pfnOriginalWSASendMsg ||
            datagramLength > ULONG_MAX ||
            operation->target.addressLength <= 0)
        {
            WSASetLastError(WSAEFAULT);
            lastError = WSAGetLastError();
            goto Cleanup;
        }
        else
        {
            WSABUF buffer;
            WSAMSG message;

            memset(&message, 0, sizeof(message));
            buffer.buf = (CHAR*)datagram;
            buffer.len = (ULONG)datagramLength;
            message.name = (LPSOCKADDR)&operation->target.address;
            message.namelen = operation->target.addressLength;
            message.lpBuffers = &buffer;
            message.dwBufferCount = 1;
            result = g_pfnOriginalWSASendMsg(
                operation->socketHandle,
                &message,
                operation->flags,
                &bytesSent,
                NULL,
                NULL);
        }
        break;

    case UDP_SEND_METHOD_SENDTO:
        if (!g_pfnOriginalSendto ||
            datagramLength > INT_MAX ||
            operation->target.addressLength <= 0)
        {
            WSASetLastError(WSAEMSGSIZE);
            lastError = WSAGetLastError();
            goto Cleanup;
        }

        result = g_pfnOriginalSendto(
            operation->socketHandle,
            (const char*)datagram,
            (int)datagramLength,
            (int)operation->flags,
            (const struct sockaddr*)&operation->target.address,
            operation->target.addressLength);
        if (result != SOCKET_ERROR)
        {
            bytesSent = (DWORD)result;
        }
        break;

    default:
        WSASetLastError(WSAEINVAL);
        lastError = WSAGetLastError();
        goto Cleanup;
    }

    if (result == SOCKET_ERROR)
    {
        lastError = WSAGetLastError();
    }

Cleanup:
    if (outResult)
    {
        outResult->result = result;
        outResult->bytesSent = bytesSent;
        outResult->lastError = lastError;
    }

    return result;
}

static void FreePendingInitialPacket(PENDING_INITIAL_PACKET* packet)
{
    if (!packet)
    {
        return;
    }

    if (packet->datagram)
    {
        free(packet->datagram);
    }

    memset(packet, 0, sizeof(*packet));
}

static void ResetPendingInitialSlot(PENDING_INITIAL_SLOT* slot)
{
    if (!slot)
    {
        return;
    }

    FreePendingInitialPacket(&slot->packet);
    memset(slot, 0, sizeof(*slot));
}

static BOOL TryGetTruncatedClientHelloPrefix(
    const unsigned char* crypto,
    SIZE_T cryptoLength,
    SIZE_T* outAvailableClientHelloLength,
    SIZE_T* outDeclaredClientHelloLength)
{
    SIZE_T availableClientHelloLength;
    SIZE_T declaredClientHelloLength;

    if (!crypto || cryptoLength < 4 || crypto[0] != 0x01)
    {
        return FALSE;
    }

    availableClientHelloLength = cryptoLength - 4;
    declaredClientHelloLength = (SIZE_T)ReadUInt24BE(crypto + 1);
    if (declaredClientHelloLength < 34)
    {
        return FALSE;
    }

    if (outAvailableClientHelloLength)
    {
        *outAvailableClientHelloLength = availableClientHelloLength;
    }

    if (outDeclaredClientHelloLength)
    {
        *outDeclaredClientHelloLength = declaredClientHelloLength;
    }

    return availableClientHelloLength < declaredClientHelloLength;
}

static DWORD WINAPI PendingInitialFlushWorker(LPVOID context)
{
    PENDING_INITIAL_FLUSH_WORK* work = (PENDING_INITIAL_FLUSH_WORK*)context;
    PENDING_INITIAL_PACKET pendingPacket;

    memset(&pendingPacket, 0, sizeof(pendingPacket));
    if (!work)
    {
        return 0;
    }

    Sleep(QUIC_PENDING_INITIAL_FLUSH_DELAY_MS);

    if (g_PendingInitialLockInitialized)
    {
        EnterCriticalSection(&g_PendingInitialLock);
        if (work->slotIndex < QUIC_PENDING_INITIAL_SLOT_COUNT &&
            g_PendingInitialSlots[work->slotIndex].active &&
            g_PendingInitialSlots[work->slotIndex].generation == work->generation)
        {
            pendingPacket = g_PendingInitialSlots[work->slotIndex].packet;
            memset(&g_PendingInitialSlots[work->slotIndex].packet, 0, sizeof(g_PendingInitialSlots[work->slotIndex].packet));
            g_PendingInitialSlots[work->slotIndex].active = FALSE;
            g_PendingInitialSlots[work->slotIndex].generation++;
            g_PendingInitialSlots[work->slotIndex].socketHandle = INVALID_SOCKET;
            g_PendingInitialSlots[work->slotIndex].version = 0;
            g_PendingInitialSlots[work->slotIndex].dcidLength = 0;
            memset(&g_PendingInitialSlots[work->slotIndex].target, 0, sizeof(g_PendingInitialSlots[work->slotIndex].target));
            memset(g_PendingInitialSlots[work->slotIndex].dcid, 0, sizeof(g_PendingInitialSlots[work->slotIndex].dcid));
        }
        LeaveCriticalSection(&g_PendingInitialLock);
    }

    if (pendingPacket.datagram)
    {
        char destinationText[96];

        FormatSendTarget(&pendingPacket.operation.target, destinationText, sizeof(destinationText));
        LogMessage(
            "[*] Flushing buffered QUIC Initial %s without rewrite after timeout (dst=%s, pn=%llu, offset=%llu)",
            pendingPacket.cryptoOffset == 0 ? "prefix" : "continuation",
            destinationText,
            pendingPacket.packetNumber,
            pendingPacket.cryptoOffset);
        SendDatagramWithOperation(
            &pendingPacket.operation,
            pendingPacket.datagram,
            pendingPacket.datagramLength,
            NULL);
        FreePendingInitialPacket(&pendingPacket);
    }

    free(work);
    return 0;
}

static BOOL TrySchedulePendingInitialFlush(DWORD slotIndex, DWORD generation)
{
    PENDING_INITIAL_FLUSH_WORK* work;

    work = (PENDING_INITIAL_FLUSH_WORK*)malloc(sizeof(*work));
    if (!work)
    {
        return FALSE;
    }

    work->slotIndex = slotIndex;
    work->generation = generation;
    if (!QueueUserWorkItem(PendingInitialFlushWorker, work, WT_EXECUTEDEFAULT))
    {
        free(work);
        return FALSE;
    }

    return TRUE;
}

static BOOL TryTakeMatchingPendingInitial(
    const UDP_SEND_OPERATION* operation,
    DWORD version,
    const unsigned char* dcid,
    unsigned char dcidLength,
    ULONGLONG cryptoOffset,
    SIZE_T cryptoLength,
    PENDING_INITIAL_PACKET* outPacket)
{
    DWORD slotIndex;
    ULONGLONG currentCryptoEnd;

    if (!g_PendingInitialLockInitialized || !operation || !dcid || !outPacket)
    {
        return FALSE;
    }

    memset(outPacket, 0, sizeof(*outPacket));
    currentCryptoEnd = cryptoOffset + (ULONGLONG)cryptoLength;

    EnterCriticalSection(&g_PendingInitialLock);
    for (slotIndex = 0; slotIndex < QUIC_PENDING_INITIAL_SLOT_COUNT; ++slotIndex)
    {
        PENDING_INITIAL_SLOT* slot = &g_PendingInitialSlots[slotIndex];
        ULONGLONG pendingCryptoEnd;

        pendingCryptoEnd = slot->packet.cryptoOffset + (ULONGLONG)slot->packet.cryptoLength;
        if (!slot->active ||
            slot->socketHandle != operation->socketHandle ||
            slot->version != version ||
            slot->dcidLength != dcidLength ||
            (slot->packet.cryptoOffset != 0 && cryptoOffset != 0) ||
            (pendingCryptoEnd != cryptoOffset && currentCryptoEnd != slot->packet.cryptoOffset) ||
            !AreSendTargetsEqual(&slot->target, &operation->target) ||
            memcmp(slot->dcid, dcid, dcidLength) != 0)
        {
            continue;
        }

        *outPacket = slot->packet;
        memset(&slot->packet, 0, sizeof(slot->packet));
        slot->active = FALSE;
        slot->generation++;
        slot->socketHandle = INVALID_SOCKET;
        slot->version = 0;
        slot->dcidLength = 0;
        memset(&slot->target, 0, sizeof(slot->target));
        memset(slot->dcid, 0, sizeof(slot->dcid));
        LeaveCriticalSection(&g_PendingInitialLock);
        return TRUE;
    }
    LeaveCriticalSection(&g_PendingInitialLock);

    return FALSE;
}

static BOOL TryBufferPendingInitial(
    const UDP_SEND_OPERATION* operation,
    unsigned char** datagram,
    SIZE_T datagramLength,
    DWORD version,
    const unsigned char* dcid,
    unsigned char dcidLength,
    ULONGLONG packetNumber,
    ULONGLONG cryptoOffset,
    SIZE_T cryptoLength,
    const char* observedSni,
    SIZE_T availableClientHelloLength,
    SIZE_T declaredClientHelloLength)
{
    PENDING_INITIAL_PACKET evictedPacket;
    DWORD slotIndex = (DWORD)-1;
    DWORD generation = 0;
    BOOL scheduled = FALSE;
    char destinationText[96];
    DWORD index;

    if (!g_PendingInitialLockInitialized ||
        !operation ||
        !datagram ||
        !*datagram ||
        !dcid ||
        dcidLength == 0)
    {
        return FALSE;
    }

    memset(&evictedPacket, 0, sizeof(evictedPacket));

    EnterCriticalSection(&g_PendingInitialLock);
    for (index = 0; index < QUIC_PENDING_INITIAL_SLOT_COUNT; ++index)
    {
        PENDING_INITIAL_SLOT* slot = &g_PendingInitialSlots[index];

        if (slot->active &&
            slot->socketHandle == operation->socketHandle &&
            slot->version == version &&
            slot->dcidLength == dcidLength &&
            AreSendTargetsEqual(&slot->target, &operation->target) &&
            memcmp(slot->dcid, dcid, dcidLength) == 0)
        {
            evictedPacket = slot->packet;
            memset(&slot->packet, 0, sizeof(slot->packet));
            slot->active = FALSE;
            slot->generation++;
            slot->socketHandle = INVALID_SOCKET;
            slot->version = 0;
            slot->dcidLength = 0;
            memset(&slot->target, 0, sizeof(slot->target));
            memset(slot->dcid, 0, sizeof(slot->dcid));
            slotIndex = index;
            break;
        }
    }

    if (slotIndex == (DWORD)-1)
    {
        for (index = 0; index < QUIC_PENDING_INITIAL_SLOT_COUNT; ++index)
        {
            if (!g_PendingInitialSlots[index].active)
            {
                slotIndex = index;
                break;
            }
        }
    }

    if (slotIndex != (DWORD)-1)
    {
        PENDING_INITIAL_SLOT* slot = &g_PendingInitialSlots[slotIndex];

        slot->active = TRUE;
        slot->generation++;
        generation = slot->generation;
        slot->socketHandle = operation->socketHandle;
        slot->version = version;
        slot->target = operation->target;
        slot->dcidLength = dcidLength;
        memcpy(slot->dcid, dcid, dcidLength);
        memset(&slot->packet, 0, sizeof(slot->packet));
        slot->packet.operation = *operation;
        slot->packet.datagram = *datagram;
        slot->packet.datagramLength = datagramLength;
        slot->packet.version = version;
        slot->packet.dcidLength = dcidLength;
        memcpy(slot->packet.dcid, dcid, dcidLength);
        slot->packet.packetNumber = packetNumber;
        slot->packet.cryptoOffset = cryptoOffset;
        slot->packet.cryptoLength = cryptoLength;
        *datagram = NULL;
    }
    LeaveCriticalSection(&g_PendingInitialLock);

    if (evictedPacket.datagram)
    {
        LogMessage(
            "[*] Replaced older buffered QUIC Initial %s before rewrite (pn=%llu, offset=%llu)",
            evictedPacket.cryptoOffset == 0 ? "prefix" : "continuation",
            evictedPacket.packetNumber,
            evictedPacket.cryptoOffset);
        SendDatagramWithOperation(
            &evictedPacket.operation,
            evictedPacket.datagram,
            evictedPacket.datagramLength,
            NULL);
        FreePendingInitialPacket(&evictedPacket);
    }

    if (slotIndex == (DWORD)-1)
    {
        return FALSE;
    }

    scheduled = TrySchedulePendingInitialFlush(slotIndex, generation);
    if (!scheduled)
    {
        PENDING_INITIAL_PACKET flushedPacket;

        memset(&flushedPacket, 0, sizeof(flushedPacket));
        EnterCriticalSection(&g_PendingInitialLock);
        if (g_PendingInitialSlots[slotIndex].active &&
            g_PendingInitialSlots[slotIndex].generation == generation)
        {
            flushedPacket = g_PendingInitialSlots[slotIndex].packet;
            memset(&g_PendingInitialSlots[slotIndex].packet, 0, sizeof(g_PendingInitialSlots[slotIndex].packet));
            g_PendingInitialSlots[slotIndex].active = FALSE;
            g_PendingInitialSlots[slotIndex].generation++;
            g_PendingInitialSlots[slotIndex].socketHandle = INVALID_SOCKET;
            g_PendingInitialSlots[slotIndex].version = 0;
            g_PendingInitialSlots[slotIndex].dcidLength = 0;
            memset(&g_PendingInitialSlots[slotIndex].target, 0, sizeof(g_PendingInitialSlots[slotIndex].target));
            memset(g_PendingInitialSlots[slotIndex].dcid, 0, sizeof(g_PendingInitialSlots[slotIndex].dcid));
        }
        LeaveCriticalSection(&g_PendingInitialLock);

        if (flushedPacket.datagram)
        {
            SendDatagramWithOperation(
                &flushedPacket.operation,
                flushedPacket.datagram,
                flushedPacket.datagramLength,
                NULL);
            FreePendingInitialPacket(&flushedPacket);
            return TRUE;
        }

        return FALSE;
    }

    FormatSendTarget(&operation->target, destinationText, sizeof(destinationText));
    if (cryptoOffset == 0)
    {
        LogMessage(
            "[*] Buffering QUIC Initial ClientHello prefix for multi-packet SNI rewrite (dst=%s, pn=%llu, sni=%s, available=%u/%u)",
            destinationText,
            packetNumber,
            observedSni ? observedSni : "unknown",
            (unsigned int)availableClientHelloLength,
            (unsigned int)declaredClientHelloLength);
    }
    else
    {
        LogMessage(
            "[*] Buffering QUIC Initial CRYPTO continuation for multi-packet SNI rewrite (dst=%s, pn=%llu, offset=%llu, crypto=%u bytes)",
            destinationText,
            packetNumber,
            cryptoOffset,
            (unsigned int)cryptoLength);
    }
    return TRUE;
}

static BOOL TryRewriteInitialPayload(
    const unsigned char* payload,
    SIZE_T payloadLength,
    unsigned char** outRewrittenPayload,
    const UDP_TRACE_CONTEXT* traceContext)
{
    QUIC_FRAME_SLICE* frames = NULL;
    SIZE_T* cryptoFrameIndexes = NULL;
    BOOL* includedCryptoFrames = NULL;
    SIZE_T frameCapacity;
    SIZE_T frameCount = 0;
    SIZE_T cursor = 0;
    SIZE_T paddingByteCount = 0;
    SIZE_T replacementFrameIndex = (SIZE_T)-1;
    SIZE_T cryptoFrameCount = 0;
    SIZE_T contiguousCryptoLength = 0;
    SIZE_T consumedCryptoFrameBytes = 0;
    unsigned char* originalCrypto = NULL;
    unsigned char* mutableCrypto = NULL;
    unsigned char* modifiedCrypto = NULL;
    SIZE_T modifiedCryptoLength = 0;
    unsigned char newCryptoFrameHeader[1 + (2 * QUIC_MAX_VARINT_LENGTH)];
    SIZE_T newCryptoFrameHeaderSize = 0;
    SIZE_T encodedSize;
    LONGLONG delta;
    SIZE_T rebuiltPaddingCount;
    unsigned char* rebuiltPayload = NULL;
    SIZE_T rebuiltOffset = 0;
    char configuredSni[MAX_PATH];
    BOOL changed = FALSE;
    SIZE_T index;

    if (!payload || !outRewrittenPayload)
    {
        return FALSE;
    }

    *outRewrittenPayload = NULL;
    if (payloadLength == 0)
    {
        return FALSE;
    }

    frameCapacity = payloadLength;
    frames = (QUIC_FRAME_SLICE*)malloc(sizeof(*frames) * frameCapacity);
    if (!frames)
    {
        return FALSE;
    }

    while (cursor < payloadLength)
    {
        if (payload[cursor] == QUIC_PADDING_FRAME_TYPE)
        {
            SIZE_T paddingStart = cursor;

            while (cursor < payloadLength && payload[cursor] == QUIC_PADDING_FRAME_TYPE)
            {
                cursor++;
            }

            paddingByteCount += cursor - paddingStart;
            continue;
        }

        if (frameCount >= frameCapacity ||
            !TryParseQuicFrame(payload, payloadLength, cursor, &frames[frameCount]))
        {
            LogPassthroughSample(
                &g_ParseFailureCount,
                "failed to parse decrypted QUIC frame",
                traceContext);
            goto Cleanup;
        }

        cursor += frames[frameCount].length;
        frameCount++;
    }

    if (frameCount == 0)
    {
        LogPassthroughSample(
            &g_NoRewriteCount,
            "no CRYPTO frame at offset 0",
            traceContext);
        goto Cleanup;
    }

    cryptoFrameIndexes = (SIZE_T*)malloc(sizeof(*cryptoFrameIndexes) * frameCount);
    includedCryptoFrames = (BOOL*)calloc(frameCount, sizeof(*includedCryptoFrames));
    if (!cryptoFrameIndexes || !includedCryptoFrames)
    {
        goto Cleanup;
    }

    for (;;)
    {
        BOOL foundNextCryptoFrame = FALSE;

        for (index = 0; index < frameCount; ++index)
        {
            const QUIC_FRAME_SLICE* frame = &frames[index];

            if (!frame->isCrypto ||
                includedCryptoFrames[index] ||
                frame->cryptoDataLength == 0 ||
                frame->cryptoOffset != (ULONGLONG)contiguousCryptoLength)
            {
                continue;
            }

            if (contiguousCryptoLength > ((SIZE_T)-1) - frame->cryptoDataLength ||
                consumedCryptoFrameBytes > ((SIZE_T)-1) - frame->length)
            {
                goto Cleanup;
            }

            includedCryptoFrames[index] = TRUE;
            cryptoFrameIndexes[cryptoFrameCount++] = index;
            contiguousCryptoLength += frame->cryptoDataLength;
            consumedCryptoFrameBytes += frame->length;
            if (replacementFrameIndex == (SIZE_T)-1 || index < replacementFrameIndex)
            {
                replacementFrameIndex = index;
            }

            foundNextCryptoFrame = TRUE;
            break;
        }

        if (!foundNextCryptoFrame)
        {
            break;
        }
    }

    if (cryptoFrameCount == 0)
    {
        LogPassthroughSample(
            &g_NoRewriteCount,
            "no CRYPTO frame at offset 0",
            traceContext);
        goto Cleanup;
    }

    if (!Config_CopySNI(configuredSni, sizeof(configuredSni)))
    {
        goto Cleanup;
    }

    originalCrypto = (unsigned char*)malloc(contiguousCryptoLength);
    mutableCrypto = (unsigned char*)malloc(contiguousCryptoLength);
    if (!originalCrypto || !mutableCrypto)
    {
        goto Cleanup;
    }

    cursor = 0;
    for (index = 0; index < cryptoFrameCount; ++index)
    {
        const QUIC_FRAME_SLICE* frame = &frames[cryptoFrameIndexes[index]];

        memcpy(
            originalCrypto + cursor,
            payload + frame->cryptoDataOffset,
            frame->cryptoDataLength);
        cursor += frame->cryptoDataLength;
    }

    memcpy(mutableCrypto, originalCrypto, contiguousCryptoLength);
    modifiedCryptoLength = contiguousCryptoLength;
    modifiedCrypto = ModifyClientHelloSNI(
        mutableCrypto,
        &modifiedCryptoLength,
        configuredSni);

    if (modifiedCryptoLength != contiguousCryptoLength ||
        (contiguousCryptoLength > 0 &&
         memcmp(modifiedCrypto, originalCrypto, contiguousCryptoLength) != 0))
    {
        changed = TRUE;
    }

    if (!changed)
    {
        LONG noRewriteCount;
        char observedSni[MAX_PATH];
        const char* observedKind = "unknown";
        char destinationText[96];

        LogPassthroughSample(
            &g_NoRewriteCount,
            cryptoFrameCount > 1
                ? "reassembled CRYPTO stream did not need SNI rewrite"
                : "CRYPTO frame did not need SNI rewrite",
            traceContext);

        noRewriteCount = InterlockedCompareExchange(&g_NoRewriteCount, 0, 0);
        if (ShouldLogHookSample(noRewriteCount))
        {
            FormatSendTarget(
                traceContext ? traceContext->target : NULL,
                destinationText,
                sizeof(destinationText));

            if (TryExtractObservedSni(
                    originalCrypto,
                    contiguousCryptoLength,
                    observedSni,
                    sizeof(observedSni),
                    &observedKind))
            {
                LogMessage(
                    "[*] QUIC CRYPTO observed SNI before rewrite (%s, dst=%s): %s",
                    observedKind,
                    destinationText,
                    observedSni);
            }
            else
            {
                LogMessage(
                    "[*] QUIC CRYPTO stream did not contain a parsable ClientHello/SNI (dst=%s, crypto=%u bytes)",
                    destinationText,
                    (unsigned int)contiguousCryptoLength);
            }
        }
        goto Cleanup;
    }

    newCryptoFrameHeader[0] = QUIC_CRYPTO_FRAME_TYPE;
    newCryptoFrameHeaderSize = 1;

    encodedSize = EncodeVarInt(
        0,
        newCryptoFrameHeader + newCryptoFrameHeaderSize,
        sizeof(newCryptoFrameHeader) - newCryptoFrameHeaderSize);
    if (encodedSize == 0)
    {
        goto Cleanup;
    }
    newCryptoFrameHeaderSize += encodedSize;

    encodedSize = EncodeVarInt(
        (ULONGLONG)modifiedCryptoLength,
        newCryptoFrameHeader + newCryptoFrameHeaderSize,
        sizeof(newCryptoFrameHeader) - newCryptoFrameHeaderSize);
    if (encodedSize == 0)
    {
        goto Cleanup;
    }
    newCryptoFrameHeaderSize += encodedSize;

    delta =
        (LONGLONG)newCryptoFrameHeaderSize +
        (LONGLONG)modifiedCryptoLength -
        (LONGLONG)consumedCryptoFrameBytes;
    if (delta > (LONGLONG)paddingByteCount)
    {
        LogPassthroughSample(
            &g_NoRewriteCount,
            "insufficient QUIC padding for longer SNI",
            traceContext);
        goto Cleanup;
    }

    if (delta >= 0)
    {
        rebuiltPaddingCount = paddingByteCount - (SIZE_T)delta;
    }
    else
    {
        SIZE_T reclaimedBytes = (SIZE_T)(-delta);

        if (paddingByteCount > ((SIZE_T)-1) - reclaimedBytes)
        {
            goto Cleanup;
        }

        rebuiltPaddingCount = paddingByteCount + reclaimedBytes;
    }

    rebuiltPayload = (unsigned char*)malloc(payloadLength);
    if (!rebuiltPayload)
    {
        goto Cleanup;
    }

    for (index = 0; index < frameCount; ++index)
    {
        if (includedCryptoFrames[index])
        {
            if (index != replacementFrameIndex)
            {
                continue;
            }

            if (newCryptoFrameHeaderSize > payloadLength - rebuiltOffset ||
                modifiedCryptoLength > payloadLength - rebuiltOffset - newCryptoFrameHeaderSize)
            {
                goto Cleanup;
            }

            memcpy(
                rebuiltPayload + rebuiltOffset,
                newCryptoFrameHeader,
                newCryptoFrameHeaderSize);
            rebuiltOffset += newCryptoFrameHeaderSize;

            memcpy(
                rebuiltPayload + rebuiltOffset,
                modifiedCrypto,
                modifiedCryptoLength);
            rebuiltOffset += modifiedCryptoLength;
            continue;
        }

        if (frames[index].length > payloadLength - rebuiltOffset)
        {
            goto Cleanup;
        }

        memcpy(
            rebuiltPayload + rebuiltOffset,
            payload + frames[index].offset,
            frames[index].length);
        rebuiltOffset += frames[index].length;
    }

    if (rebuiltPaddingCount > payloadLength - rebuiltOffset)
    {
        goto Cleanup;
    }

    memset(rebuiltPayload + rebuiltOffset, 0, rebuiltPaddingCount);
    rebuiltOffset += rebuiltPaddingCount;

    if (rebuiltOffset != payloadLength)
    {
        goto Cleanup;
    }

    *outRewrittenPayload = rebuiltPayload;
    rebuiltPayload = NULL;

Cleanup:
    if (modifiedCrypto && modifiedCrypto != mutableCrypto)
    {
        free(modifiedCrypto);
    }

    if (mutableCrypto)
    {
        free(mutableCrypto);
    }

    if (originalCrypto)
    {
        free(originalCrypto);
    }

    if (rebuiltPayload)
    {
        free(rebuiltPayload);
    }

    if (includedCryptoFrames)
    {
        free(includedCryptoFrames);
    }

    if (cryptoFrameIndexes)
    {
        free(cryptoFrameIndexes);
    }

    if (frames)
    {
        free(frames);
    }

    return *outRewrittenPayload != NULL;
}

static BOOL TryRewriteDatagramInPlace(
    unsigned char* datagram,
    SIZE_T datagramLength,
    const UDP_TRACE_CONTEXT* traceContext)
{
    QUIC_PACKET_METADATA metadata;
    QUIC_INITIAL_KEYS keys;
    unsigned char nonce[QUIC_AEAD_IV_LENGTH];
    unsigned char* originalDatagram = NULL;
    unsigned char* plaintext = NULL;
    unsigned char* rewrittenPayload = NULL;
    BOOL modified = FALSE;
    char destinationText[96];

    if (!datagram || datagramLength == 0)
    {
        return FALSE;
    }

    originalDatagram = (unsigned char*)malloc(datagramLength);
    if (!originalDatagram)
    {
        return FALSE;
    }

    memcpy(originalDatagram, datagram, datagramLength);

    if (!TryParseProtectedInitialPacket(
            datagram,
            datagramLength,
            &metadata,
            traceContext))
    {
        return FALSE;
    }

    if (!DeriveClientInitialKeys(metadata.version, metadata.dcid, metadata.dcidLength, &keys))
    {
        LogPassthroughSample(
            &g_ParseFailureCount,
            "failed to derive QUIC Initial keys",
            traceContext);
        return FALSE;
    }

    if (!RemoveHeaderProtection(datagram, &keys, &metadata))
    {
        LogPassthroughSample(
            &g_ParseFailureCount,
            "failed to remove QUIC header protection",
            traceContext);
        return FALSE;
    }

    BuildPacketNonce(keys.packetIv, metadata.packetNumber, nonce);

    plaintext = (unsigned char*)malloc(metadata.plaintextLength);
    if (!plaintext)
    {
        return FALSE;
    }

    if (!DecryptAes128Gcm(
            keys.packetKey,
            nonce,
            datagram,
            (ULONG)metadata.headerLength,
            datagram + metadata.ciphertextOffset,
            (ULONG)metadata.plaintextLength,
            datagram + metadata.ciphertextOffset + metadata.plaintextLength,
            plaintext))
    {
        LogPassthroughSample(
            &g_ParseFailureCount,
            "failed to decrypt QUIC Initial payload",
            traceContext);
        goto Cleanup;
    }

    if (!TryRewriteInitialPayload(
            plaintext,
            metadata.plaintextLength,
            &rewrittenPayload,
            traceContext))
    {
        goto Cleanup;
    }

    if (!EncryptAes128Gcm(
            keys.packetKey,
            nonce,
            datagram,
            (ULONG)metadata.headerLength,
            rewrittenPayload,
            (ULONG)metadata.plaintextLength,
            datagram + metadata.ciphertextOffset,
            datagram + metadata.ciphertextOffset + metadata.plaintextLength))
    {
        goto Cleanup;
    }

    ApplyHeaderProtection(datagram, &keys, &metadata);
    RegisterHookHit(&g_RewriteSuccessCount);
    FormatSendTarget(
        traceContext ? traceContext->target : NULL,
        destinationText,
        sizeof(destinationText));
    LogMessage(
        "[+] Rewrote QUIC Initial packet SNI (%s, dst=%s, pn=%llu, %u bytes)",
        metadata.version == QUIC_VERSION_2 ? "v2" : "v1",
        destinationText,
        metadata.packetNumber,
        (unsigned int)metadata.packetLength);
    modified = TRUE;

Cleanup:
    if (!modified && originalDatagram)
    {
        memcpy(datagram, originalDatagram, datagramLength);
    }

    if (originalDatagram)
    {
        free(originalDatagram);
    }

    if (rewrittenPayload)
    {
        free(rewrittenPayload);
    }

    if (plaintext)
    {
        free(plaintext);
    }

    return modified;
}

static BOOL TrySendBufferedRewritePair(
    const PENDING_INITIAL_PACKET* pendingPacket,
    const UDP_SEND_OPERATION* currentOperation,
    const unsigned char* currentDatagram,
    SIZE_T currentDatagramLength,
    PREPARED_INITIAL_PACKET* currentPrepared,
    const UDP_TRACE_CONTEXT* traceContext,
    UDP_SEND_RESULT* outCurrentResult)
{
    PREPARED_INITIAL_PACKET pendingPrepared;
    PREPARED_INITIAL_PACKET* prefixPrepared;
    PREPARED_INITIAL_PACKET* continuationPrepared;
    UDP_TRACE_CONTEXT pendingTrace;
    const UDP_SEND_OPERATION* prefixOperation;
    const UDP_SEND_OPERATION* continuationOperation;
    const unsigned char* prefixOriginalDatagram;
    const unsigned char* continuationOriginalDatagram;
    SIZE_T prefixOriginalDatagramLength;
    SIZE_T continuationOriginalDatagramLength;
    BOOL prefixIsCurrent;
    unsigned char* prefixCrypto = NULL;
    unsigned char* continuationCrypto = NULL;
    unsigned char* fullCrypto = NULL;
    unsigned char* mutableCrypto = NULL;
    unsigned char* modifiedCrypto = NULL;
    unsigned char* rewrittenPrefixPayload = NULL;
    unsigned char* rewrittenContinuationPayload = NULL;
    SIZE_T modifiedCryptoLength = 0;
    SIZE_T prefixCryptoLength;
    SIZE_T continuationCryptoLength;
    SIZE_T continuationRewrittenLength;
    char configuredSni[MAX_PATH];
    char destinationText[96];
    UDP_SEND_RESULT currentSendResult;
    BOOL currentSendIssued = FALSE;
    BOOL success = FALSE;

    memset(&pendingPrepared, 0, sizeof(pendingPrepared));
    pendingPrepared.cryptoRun.replacementFrameIndex = (SIZE_T)-1;
    memset(&currentSendResult, 0, sizeof(currentSendResult));

    if (!pendingPacket ||
        !currentOperation ||
        !currentDatagram ||
        currentDatagramLength == 0 ||
        !currentPrepared)
    {
        return FALSE;
    }

    pendingTrace.target = &pendingPacket->operation.target;
    pendingTrace.datagram = pendingPacket->datagram;
    pendingTrace.datagramLength = pendingPacket->datagramLength;
    if (!TryPrepareInitialPacket(
            pendingPacket->datagram,
            pendingPacket->datagramLength,
            &pendingTrace,
            &pendingPrepared))
    {
        goto FallbackToOriginal;
    }

    if ((pendingPrepared.cryptoRun.startOffset == 0) == (currentPrepared->cryptoRun.startOffset == 0))
    {
        goto FallbackToOriginal;
    }

    if (pendingPrepared.cryptoRun.startOffset == 0)
    {
        prefixPrepared = &pendingPrepared;
        continuationPrepared = currentPrepared;
        prefixOperation = &pendingPacket->operation;
        continuationOperation = currentOperation;
        prefixOriginalDatagram = pendingPacket->datagram;
        continuationOriginalDatagram = currentDatagram;
        prefixOriginalDatagramLength = pendingPacket->datagramLength;
        continuationOriginalDatagramLength = currentDatagramLength;
        prefixIsCurrent = FALSE;
    }
    else
    {
        prefixPrepared = currentPrepared;
        continuationPrepared = &pendingPrepared;
        prefixOperation = currentOperation;
        continuationOperation = &pendingPacket->operation;
        prefixOriginalDatagram = currentDatagram;
        continuationOriginalDatagram = pendingPacket->datagram;
        prefixOriginalDatagramLength = currentDatagramLength;
        continuationOriginalDatagramLength = pendingPacket->datagramLength;
        prefixIsCurrent = TRUE;
    }

    if (continuationPrepared->cryptoRun.startOffset !=
        prefixPrepared->cryptoRun.startOffset + (ULONGLONG)prefixPrepared->cryptoRun.contiguousCryptoLength)
    {
        goto FallbackToOriginal;
    }

    prefixCrypto = CopyCryptoRunBytes(prefixPrepared->plaintext, &prefixPrepared->cryptoRun);
    continuationCrypto = CopyCryptoRunBytes(continuationPrepared->plaintext, &continuationPrepared->cryptoRun);
    if (!prefixCrypto || !continuationCrypto)
    {
        goto FallbackToOriginal;
    }

    prefixCryptoLength = prefixPrepared->cryptoRun.contiguousCryptoLength;
    continuationCryptoLength = continuationPrepared->cryptoRun.contiguousCryptoLength;
    fullCrypto = (unsigned char*)malloc(prefixCryptoLength + continuationCryptoLength);
    mutableCrypto = (unsigned char*)malloc(prefixCryptoLength + continuationCryptoLength);
    if (!fullCrypto || !mutableCrypto)
    {
        goto FallbackToOriginal;
    }

    memcpy(fullCrypto, prefixCrypto, prefixCryptoLength);
    memcpy(fullCrypto + prefixCryptoLength, continuationCrypto, continuationCryptoLength);
    memcpy(mutableCrypto, fullCrypto, prefixCryptoLength + continuationCryptoLength);

    if (!Config_CopySNI(configuredSni, sizeof(configuredSni)))
    {
        goto FallbackToOriginal;
    }
    modifiedCryptoLength = prefixCryptoLength + continuationCryptoLength;
    modifiedCrypto = ModifyClientHelloSNI(
        mutableCrypto,
        &modifiedCryptoLength,
        configuredSni);
    if (!modifiedCrypto ||
        (modifiedCryptoLength == prefixCryptoLength + continuationCryptoLength &&
         memcmp(modifiedCrypto, fullCrypto, modifiedCryptoLength) == 0))
    {
        goto FallbackToOriginal;
    }

    if (modifiedCryptoLength <= prefixCryptoLength)
    {
        goto FallbackToOriginal;
    }

    continuationRewrittenLength = modifiedCryptoLength - prefixCryptoLength;
    if (!BuildRewrittenPayloadFromCryptoRun(
            prefixPrepared->plaintext,
            prefixPrepared->metadata.plaintextLength,
            &prefixPrepared->cryptoRun,
            0,
            modifiedCrypto,
            prefixCryptoLength,
            &rewrittenPrefixPayload) ||
        !BuildRewrittenPayloadFromCryptoRun(
            continuationPrepared->plaintext,
            continuationPrepared->metadata.plaintextLength,
            &continuationPrepared->cryptoRun,
            prefixCryptoLength,
            modifiedCrypto + prefixCryptoLength,
            continuationRewrittenLength,
            &rewrittenContinuationPayload))
    {
        goto FallbackToOriginal;
    }

    if (!ApplyRewrittenPayloadToPreparedInitial(prefixPrepared, rewrittenPrefixPayload) ||
        !ApplyRewrittenPayloadToPreparedInitial(continuationPrepared, rewrittenContinuationPayload))
    {
        goto FallbackToOriginal;
    }

    FormatSendTarget(
        traceContext ? traceContext->target : &currentOperation->target,
        destinationText,
        sizeof(destinationText));

    if (prefixPrepared->metadata.packetNumber <= continuationPrepared->metadata.packetNumber)
    {
        SendDatagramWithOperation(
            prefixOperation,
            prefixPrepared->datagram,
            prefixPrepared->datagramLength,
            prefixIsCurrent ? &currentSendResult : NULL);
        currentSendIssued = prefixIsCurrent;
        SendDatagramWithOperation(
            continuationOperation,
            continuationPrepared->datagram,
            continuationPrepared->datagramLength,
            prefixIsCurrent ? NULL : &currentSendResult);
        if (!prefixIsCurrent)
        {
            currentSendIssued = TRUE;
        }
    }
    else
    {
        SendDatagramWithOperation(
            continuationOperation,
            continuationPrepared->datagram,
            continuationPrepared->datagramLength,
            prefixIsCurrent ? NULL : &currentSendResult);
        if (!prefixIsCurrent)
        {
            currentSendIssued = TRUE;
        }
        SendDatagramWithOperation(
            prefixOperation,
            prefixPrepared->datagram,
            prefixPrepared->datagramLength,
            prefixIsCurrent ? &currentSendResult : NULL);
        if (prefixIsCurrent)
        {
            currentSendIssued = TRUE;
        }
    }

    RegisterHookHit(&g_RewriteSuccessCount);
    RegisterHookHit(&g_RewriteSuccessCount);
    LogMessage(
        "[+] Rewrote buffered QUIC Initial SNI across 2 packets (%s, dst=%s, pn=%llu/%llu, crypto=%u -> %u bytes)",
        prefixPrepared->metadata.version == QUIC_VERSION_2 ? "v2" : "v1",
        destinationText,
        prefixPrepared->metadata.packetNumber,
        continuationPrepared->metadata.packetNumber,
        (unsigned int)(prefixCryptoLength + continuationCryptoLength),
        (unsigned int)modifiedCryptoLength);
    success = TRUE;
    goto Cleanup;

FallbackToOriginal:
    if (pendingPacket->packetNumber > currentPrepared->metadata.packetNumber)
    {
        SendDatagramWithOperation(
            currentOperation,
            currentDatagram,
            currentDatagramLength,
            &currentSendResult);
        currentSendIssued = TRUE;
        SendDatagramWithOperation(
            &pendingPacket->operation,
            pendingPacket->datagram,
            pendingPacket->datagramLength,
            NULL);
    }
    else
    {
        SendDatagramWithOperation(
            &pendingPacket->operation,
            pendingPacket->datagram,
            pendingPacket->datagramLength,
            NULL);
        SendDatagramWithOperation(
            currentOperation,
            currentDatagram,
            currentDatagramLength,
            &currentSendResult);
        currentSendIssued = TRUE;
    }

Cleanup:
    if (outCurrentResult && currentSendIssued)
    {
        *outCurrentResult = currentSendResult;
    }

    if (rewrittenContinuationPayload)
    {
        free(rewrittenContinuationPayload);
    }

    if (rewrittenPrefixPayload)
    {
        free(rewrittenPrefixPayload);
    }

    if (modifiedCrypto && modifiedCrypto != mutableCrypto)
    {
        free(modifiedCrypto);
    }

    if (mutableCrypto)
    {
        free(mutableCrypto);
    }

    if (fullCrypto)
    {
        free(fullCrypto);
    }

    if (continuationCrypto)
    {
        free(continuationCrypto);
    }

    if (prefixCrypto)
    {
        free(prefixCrypto);
    }

    FreePreparedInitialPacket(&pendingPrepared);
    return success || currentSendIssued;
}

static UDP_SEND_DECISION TryHandleBufferedInitialRewrite(
    const UDP_SEND_OPERATION* operation,
    unsigned char** datagram,
    SIZE_T datagramLength,
    const UDP_TRACE_CONTEXT* traceContext,
    UDP_SEND_RESULT* outCurrentResult)
{
    PREPARED_INITIAL_PACKET currentPrepared;
    PENDING_INITIAL_PACKET pendingPacket;
    unsigned char* crypto = NULL;
    char observedSni[MAX_PATH];
    char configuredSni[MAX_PATH];
    const char* observedKind = "unknown";
    SIZE_T availableClientHelloLength = 0;
    SIZE_T declaredClientHelloLength = 0;
    BOOL haveObservedSni = FALSE;
    UDP_SEND_DECISION decision = UDP_SEND_DECISION_FALLTHROUGH;

    memset(&currentPrepared, 0, sizeof(currentPrepared));
    currentPrepared.cryptoRun.replacementFrameIndex = (SIZE_T)-1;
    memset(&pendingPacket, 0, sizeof(pendingPacket));

    if (!operation || !datagram || !*datagram || datagramLength == 0)
    {
        return UDP_SEND_DECISION_FALLTHROUGH;
    }

    if (!TryPrepareInitialPacket(*datagram, datagramLength, traceContext, &currentPrepared))
    {
        goto Cleanup;
    }

    if (TryTakeMatchingPendingInitial(
            operation,
            currentPrepared.metadata.version,
            currentPrepared.metadata.dcid,
            currentPrepared.metadata.dcidLength,
            currentPrepared.cryptoRun.startOffset,
            currentPrepared.cryptoRun.contiguousCryptoLength,
            &pendingPacket))
    {
        if (TrySendBufferedRewritePair(
                &pendingPacket,
                operation,
                *datagram,
                datagramLength,
                &currentPrepared,
                traceContext,
                outCurrentResult))
        {
            decision = UDP_SEND_DECISION_SENT_INTERNAL;
        }

        goto Cleanup;
    }

    if (currentPrepared.cryptoRun.startOffset != 0)
    {
        if (TryBufferPendingInitial(
                operation,
                datagram,
                datagramLength,
                currentPrepared.metadata.version,
                currentPrepared.metadata.dcid,
                currentPrepared.metadata.dcidLength,
                currentPrepared.metadata.packetNumber,
                currentPrepared.cryptoRun.startOffset,
                currentPrepared.cryptoRun.contiguousCryptoLength,
                NULL,
                0,
                0))
        {
            decision = UDP_SEND_DECISION_BUFFERED;
        }

        goto Cleanup;
    }

    crypto = CopyCryptoRunBytes(currentPrepared.plaintext, &currentPrepared.cryptoRun);
    if (!crypto)
    {
        goto Cleanup;
    }

    haveObservedSni = TryExtractObservedSni(
        crypto,
        currentPrepared.cryptoRun.contiguousCryptoLength,
        observedSni,
        sizeof(observedSni),
        &observedKind);
    if (!haveObservedSni ||
        !IsKnownWarpMasqueSni(observedSni) ||
        !TryGetTruncatedClientHelloPrefix(
            crypto,
            currentPrepared.cryptoRun.contiguousCryptoLength,
            &availableClientHelloLength,
            &declaredClientHelloLength))
    {
        goto Cleanup;
    }

    if (!Config_CopySNI(configuredSni, sizeof(configuredSni)))
    {
        goto Cleanup;
    }
    if (_stricmp(observedSni, configuredSni) == 0 ||
        strlen(observedSni) == strlen(configuredSni))
    {
        goto Cleanup;
    }

    if (TryBufferPendingInitial(
            operation,
            datagram,
            datagramLength,
            currentPrepared.metadata.version,
            currentPrepared.metadata.dcid,
            currentPrepared.metadata.dcidLength,
            currentPrepared.metadata.packetNumber,
            currentPrepared.cryptoRun.startOffset,
            currentPrepared.cryptoRun.contiguousCryptoLength,
            observedSni,
            availableClientHelloLength,
            declaredClientHelloLength))
    {
        decision = UDP_SEND_DECISION_BUFFERED;
    }

Cleanup:
    if (crypto)
    {
        free(crypto);
    }

    FreePendingInitialPacket(&pendingPacket);
    FreePreparedInitialPacket(&currentPrepared);
    return decision;
}

static unsigned char* FlattenWsabufs(
    const WSABUF* buffers,
    DWORD bufferCount,
    SIZE_T* outLength)
{
    SIZE_T totalLength = 0;
    SIZE_T cursor = 0;
    unsigned char* flattened = NULL;
    DWORD bufferIndex;

    if (!buffers || bufferCount == 0 || !outLength)
    {
        return NULL;
    }

    for (bufferIndex = 0; bufferIndex < bufferCount; ++bufferIndex)
    {
        if ((SIZE_T)buffers[bufferIndex].len > ((SIZE_T)-1) - totalLength)
        {
            return NULL;
        }

        totalLength += buffers[bufferIndex].len;
    }

    flattened = (unsigned char*)malloc(totalLength);
    if (!flattened)
    {
        return NULL;
    }

    for (bufferIndex = 0; bufferIndex < bufferCount; ++bufferIndex)
    {
        if (buffers[bufferIndex].len > 0)
        {
            memcpy(
                flattened + cursor,
                buffers[bufferIndex].buf,
                buffers[bufferIndex].len);
            cursor += buffers[bufferIndex].len;
        }
    }

    *outLength = totalLength;
    return flattened;
}

static int WINAPI Hooked_send(
    SOCKET s,
    const char* buf,
    int len,
    int flags)
{
    BOOL isDatagram;
    unsigned char* mutableDatagram;
#if WARPS_ENABLE_STREAM_TLS_REWRITE
    unsigned char* modifiedTlsBuffer = NULL;
    SIZE_T modifiedTlsLength = 0;
#endif
    UDP_SEND_OPERATION operation;
    UDP_SEND_RESULT sendResult;
    UDP_SEND_DECISION decision;
    UDP_SEND_TARGET target;
    UDP_TRACE_CONTEXT traceContext;
    int result;

    RegisterHookHit(&g_sendHitCount);

    if (!g_pfnOriginalSend)
    {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    if (!buf || len <= 0)
    {
        return g_pfnOriginalSend(s, buf, len, flags);
    }

    if (!ResolveSendTarget(s, NULL, 0, &target) ||
        GetSendTargetPort(&target) != QUIC_TARGET_UDP_PORT)
    {
        return g_pfnOriginalSend(s, buf, len, flags);
    }

    isDatagram = IsDatagramSocket(s);
    if (!isDatagram)
    {
#if WARPS_ENABLE_STREAM_TLS_REWRITE
        if (!IsStreamSocket(s))
        {
            return g_pfnOriginalSend(s, buf, len, flags);
        }

        modifiedTlsBuffer = CreateModifiedTlsClientHelloCopy(
            "send",
            &target,
            (const unsigned char*)buf,
            (SIZE_T)len,
            &modifiedTlsLength);
        if (!modifiedTlsBuffer || modifiedTlsLength > INT_MAX)
        {
            if (modifiedTlsBuffer)
            {
                free(modifiedTlsBuffer);
            }

            return g_pfnOriginalSend(s, buf, len, flags);
        }

        result = g_pfnOriginalSend(
            s,
            (const char*)modifiedTlsBuffer,
            (int)modifiedTlsLength,
            flags);
        free(modifiedTlsBuffer);
        return result;
#else
        return g_pfnOriginalSend(s, buf, len, flags);
#endif
    }

    mutableDatagram = (unsigned char*)malloc((SIZE_T)len);
    if (!mutableDatagram)
    {
        return g_pfnOriginalSend(s, buf, len, flags);
    }

    memcpy(mutableDatagram, buf, (SIZE_T)len);
    traceContext.target = &target;
    traceContext.datagram = mutableDatagram;
    traceContext.datagramLength = (SIZE_T)len;
    operation.method = UDP_SEND_METHOD_SEND;
    operation.socketHandle = s;
    operation.flags = (DWORD)flags;
    operation.target = target;
    if (!TryRewriteDatagramInPlace(mutableDatagram, (SIZE_T)len, &traceContext))
    {
        memset(&sendResult, 0, sizeof(sendResult));
        decision = TryHandleBufferedInitialRewrite(
            &operation,
            &mutableDatagram,
            (SIZE_T)len,
            &traceContext,
            &sendResult);
        if (decision == UDP_SEND_DECISION_BUFFERED)
        {
            return len;
        }

        if (decision == UDP_SEND_DECISION_SENT_INTERNAL)
        {
            if (mutableDatagram)
            {
                free(mutableDatagram);
            }

            if (sendResult.result == SOCKET_ERROR && sendResult.lastError != 0)
            {
                WSASetLastError(sendResult.lastError);
            }

            return sendResult.result;
        }
    }

    result = SendDatagramWithOperation(&operation, mutableDatagram, (SIZE_T)len, &sendResult);
    free(mutableDatagram);
    if (result == SOCKET_ERROR && sendResult.lastError != 0)
    {
        WSASetLastError(sendResult.lastError);
    }
    return result;
}

static int WSAAPI Hooked_WSASend(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    BOOL isDatagram;
    SIZE_T flattenedLength = 0;
    unsigned char* flattenedDatagram = NULL;
#if WARPS_ENABLE_STREAM_TLS_REWRITE
    unsigned char* modifiedTlsBuffer = NULL;
    SIZE_T modifiedTlsLength = 0;
#endif
    UDP_SEND_OPERATION operation;
    UDP_SEND_RESULT sendResult;
    UDP_SEND_DECISION decision;
    UDP_SEND_TARGET target;
    UDP_TRACE_CONTEXT traceContext;
    int result;

    RegisterHookHit(&g_WSASendHitCount);

    if (!g_pfnOriginalWSASend)
    {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    if (!lpBuffers || dwBufferCount == 0)
    {
        return g_pfnOriginalWSASend(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesSent,
            dwFlags,
            lpOverlapped,
            lpCompletionRoutine);
    }

    if (!ResolveSendTarget(s, NULL, 0, &target) ||
        GetSendTargetPort(&target) != QUIC_TARGET_UDP_PORT)
    {
        return g_pfnOriginalWSASend(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesSent,
            dwFlags,
            lpOverlapped,
            lpCompletionRoutine);
    }

    isDatagram = IsDatagramSocket(s);
    if (!isDatagram)
    {
#if WARPS_ENABLE_STREAM_TLS_REWRITE
        if (!IsStreamSocket(s))
        {
            return g_pfnOriginalWSASend(
                s,
                lpBuffers,
                dwBufferCount,
                lpNumberOfBytesSent,
                dwFlags,
                lpOverlapped,
                lpCompletionRoutine);
        }

        if (lpOverlapped || lpCompletionRoutine)
        {
            return g_pfnOriginalWSASend(
                s,
                lpBuffers,
                dwBufferCount,
                lpNumberOfBytesSent,
                dwFlags,
                lpOverlapped,
                lpCompletionRoutine);
        }

        flattenedDatagram = FlattenWsabufs(lpBuffers, dwBufferCount, &flattenedLength);
        if (!flattenedDatagram)
        {
            return g_pfnOriginalWSASend(
                s,
                lpBuffers,
                dwBufferCount,
                lpNumberOfBytesSent,
                dwFlags,
                lpOverlapped,
                lpCompletionRoutine);
        }

        modifiedTlsBuffer = CreateModifiedTlsClientHelloCopy(
            "WSASend",
            &target,
            flattenedDatagram,
            flattenedLength,
            &modifiedTlsLength);
        free(flattenedDatagram);
        if (!modifiedTlsBuffer || modifiedTlsLength > ULONG_MAX)
        {
            if (modifiedTlsBuffer)
            {
                free(modifiedTlsBuffer);
            }

            return g_pfnOriginalWSASend(
                s,
                lpBuffers,
                dwBufferCount,
                lpNumberOfBytesSent,
                dwFlags,
                lpOverlapped,
                lpCompletionRoutine);
        }

        {
            WSABUF modifiedBuffer;
            DWORD bytesSent = 0;

            modifiedBuffer.buf = (CHAR*)modifiedTlsBuffer;
            modifiedBuffer.len = (ULONG)modifiedTlsLength;
            result = g_pfnOriginalWSASend(
                s,
                &modifiedBuffer,
                1,
                &bytesSent,
                dwFlags,
                NULL,
                NULL);

            if (lpNumberOfBytesSent && result != SOCKET_ERROR)
            {
                *lpNumberOfBytesSent = bytesSent;
            }
        }

        free(modifiedTlsBuffer);
        return result;
#else
        return g_pfnOriginalWSASend(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesSent,
            dwFlags,
            lpOverlapped,
            lpCompletionRoutine);
#endif
    }

    traceContext.target = &target;
    traceContext.datagram = NULL;
    traceContext.datagramLength = 0;

    if (lpOverlapped || lpCompletionRoutine)
    {
        LogPassthroughSample(
            &g_AsyncWsasendPassthroughCount,
            "asynchronous WSASend",
            &traceContext);
        return g_pfnOriginalWSASend(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesSent,
            dwFlags,
            lpOverlapped,
            lpCompletionRoutine);
    }

    flattenedDatagram = FlattenWsabufs(lpBuffers, dwBufferCount, &flattenedLength);
    if (!flattenedDatagram || flattenedLength > ULONG_MAX)
    {
        if (flattenedDatagram)
        {
            free(flattenedDatagram);
        }

        return g_pfnOriginalWSASend(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesSent,
            dwFlags,
            lpOverlapped,
            lpCompletionRoutine);
    }

    traceContext.datagram = flattenedDatagram;
    traceContext.datagramLength = flattenedLength;
    operation.method = UDP_SEND_METHOD_WSASEND;
    operation.socketHandle = s;
    operation.flags = dwFlags;
    operation.target = target;
    if (!TryRewriteDatagramInPlace(flattenedDatagram, flattenedLength, &traceContext))
    {
        memset(&sendResult, 0, sizeof(sendResult));
        decision = TryHandleBufferedInitialRewrite(
            &operation,
            &flattenedDatagram,
            flattenedLength,
            &traceContext,
            &sendResult);
        if (decision == UDP_SEND_DECISION_BUFFERED)
        {
            if (lpNumberOfBytesSent)
            {
                *lpNumberOfBytesSent = (DWORD)flattenedLength;
            }

            return 0;
        }

        if (decision == UDP_SEND_DECISION_SENT_INTERNAL)
        {
            if (flattenedDatagram)
            {
                free(flattenedDatagram);
            }

            if (lpNumberOfBytesSent && sendResult.result != SOCKET_ERROR)
            {
                *lpNumberOfBytesSent = sendResult.bytesSent;
            }

            if (sendResult.result == SOCKET_ERROR && sendResult.lastError != 0)
            {
                WSASetLastError(sendResult.lastError);
            }

            return sendResult.result;
        }
    }

    result = SendDatagramWithOperation(&operation, flattenedDatagram, flattenedLength, &sendResult);
    if (lpNumberOfBytesSent && result != SOCKET_ERROR)
    {
        *lpNumberOfBytesSent = sendResult.bytesSent;
    }

    free(flattenedDatagram);
    if (result == SOCKET_ERROR && sendResult.lastError != 0)
    {
        WSASetLastError(sendResult.lastError);
    }

    return result;
}

static int WINAPI Hooked_WSASendTo(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    const struct sockaddr* lpTo,
    int iTolen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    SIZE_T flattenedLength = 0;
    unsigned char* flattenedDatagram = NULL;
    UDP_SEND_OPERATION operation;
    UDP_SEND_RESULT sendResult;
    UDP_SEND_DECISION decision;
    UDP_SEND_TARGET target;
    UDP_TRACE_CONTEXT traceContext;
    int result;

    RegisterHookHit(&g_WSASendToHitCount);

    if (!g_pfnOriginalWSASendTo)
    {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    if (!ResolveSendTarget(s, lpTo, iTolen, &target) ||
        GetSendTargetPort(&target) != QUIC_TARGET_UDP_PORT)
    {
        return g_pfnOriginalWSASendTo(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesSent,
            dwFlags,
            lpTo,
            iTolen,
            lpOverlapped,
            lpCompletionRoutine);
    }

    traceContext.target = &target;
    traceContext.datagram = NULL;
    traceContext.datagramLength = 0;

    if (lpOverlapped || lpCompletionRoutine)
    {
        LogPassthroughSample(
            &g_AsyncWsasendtoPassthroughCount,
            "asynchronous WSASendTo",
            &traceContext);
        return g_pfnOriginalWSASendTo(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesSent,
            dwFlags,
            lpTo,
            iTolen,
            lpOverlapped,
            lpCompletionRoutine);
    }

    flattenedDatagram = FlattenWsabufs(lpBuffers, dwBufferCount, &flattenedLength);
    if (!flattenedDatagram || flattenedLength > ULONG_MAX)
    {
        if (flattenedDatagram)
        {
            free(flattenedDatagram);
        }

        return g_pfnOriginalWSASendTo(
            s,
            lpBuffers,
            dwBufferCount,
            lpNumberOfBytesSent,
            dwFlags,
            lpTo,
            iTolen,
            lpOverlapped,
            lpCompletionRoutine);
    }

    traceContext.datagram = flattenedDatagram;
    traceContext.datagramLength = flattenedLength;
    operation.method = UDP_SEND_METHOD_WSASENDTO;
    operation.socketHandle = s;
    operation.flags = dwFlags;
    operation.target = target;
    if (!TryRewriteDatagramInPlace(flattenedDatagram, flattenedLength, &traceContext))
    {
        memset(&sendResult, 0, sizeof(sendResult));
        decision = TryHandleBufferedInitialRewrite(
            &operation,
            &flattenedDatagram,
            flattenedLength,
            &traceContext,
            &sendResult);
        if (decision == UDP_SEND_DECISION_BUFFERED)
        {
            if (lpNumberOfBytesSent)
            {
                *lpNumberOfBytesSent = (DWORD)flattenedLength;
            }

            return 0;
        }

        if (decision == UDP_SEND_DECISION_SENT_INTERNAL)
        {
            if (flattenedDatagram)
            {
                free(flattenedDatagram);
            }

            if (lpNumberOfBytesSent && sendResult.result != SOCKET_ERROR)
            {
                *lpNumberOfBytesSent = sendResult.bytesSent;
            }

            if (sendResult.result == SOCKET_ERROR && sendResult.lastError != 0)
            {
                WSASetLastError(sendResult.lastError);
            }

            return sendResult.result;
        }
    }

    result = SendDatagramWithOperation(&operation, flattenedDatagram, flattenedLength, &sendResult);
    if (lpNumberOfBytesSent && result != SOCKET_ERROR)
    {
        *lpNumberOfBytesSent = sendResult.bytesSent;
    }

    free(flattenedDatagram);
    if (result == SOCKET_ERROR && sendResult.lastError != 0)
    {
        WSASetLastError(sendResult.lastError);
    }

    return result;
}

static INT WSAAPI Hooked_WSASendMsg(
    SOCKET s,
    LPWSAMSG lpMsg,
    DWORD dwFlags,
    LPDWORD lpNumberOfBytesSent,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    SIZE_T flattenedLength = 0;
    unsigned char* flattenedDatagram = NULL;
    UDP_SEND_OPERATION operation;
    UDP_SEND_RESULT sendResult;
    UDP_SEND_DECISION decision;
    UDP_SEND_TARGET target;
    UDP_TRACE_CONTEXT traceContext;
    int result;

    RegisterHookHit(&g_WSASendMsgHitCount);

    if (!g_pfnOriginalWSASendMsg)
    {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    if (!lpMsg || !lpMsg->lpBuffers || lpMsg->dwBufferCount == 0)
    {
        return g_pfnOriginalWSASendMsg(
            s,
            lpMsg,
            dwFlags,
            lpNumberOfBytesSent,
            lpOverlapped,
            lpCompletionRoutine);
    }

    if (!ResolveSendTarget(s, lpMsg->name, lpMsg->namelen, &target) ||
        GetSendTargetPort(&target) != QUIC_TARGET_UDP_PORT)
    {
        return g_pfnOriginalWSASendMsg(
            s,
            lpMsg,
            dwFlags,
            lpNumberOfBytesSent,
            lpOverlapped,
            lpCompletionRoutine);
    }

    traceContext.target = &target;
    traceContext.datagram = NULL;
    traceContext.datagramLength = 0;

    if (lpOverlapped || lpCompletionRoutine)
    {
        LogPassthroughSample(
            &g_AsyncWsasendmsgPassthroughCount,
            "asynchronous WSASendMsg",
            &traceContext);
        return g_pfnOriginalWSASendMsg(
            s,
            lpMsg,
            dwFlags,
            lpNumberOfBytesSent,
            lpOverlapped,
            lpCompletionRoutine);
    }

    flattenedDatagram = FlattenWsabufs(lpMsg->lpBuffers, lpMsg->dwBufferCount, &flattenedLength);
    if (!flattenedDatagram || flattenedLength > ULONG_MAX)
    {
        if (flattenedDatagram)
        {
            free(flattenedDatagram);
        }

        return g_pfnOriginalWSASendMsg(
            s,
            lpMsg,
            dwFlags,
            lpNumberOfBytesSent,
            lpOverlapped,
            lpCompletionRoutine);
    }

    traceContext.datagram = flattenedDatagram;
    traceContext.datagramLength = flattenedLength;
    operation.method = UDP_SEND_METHOD_WSASENDMSG;
    operation.socketHandle = s;
    operation.flags = dwFlags;
    operation.target = target;
    if (!TryRewriteDatagramInPlace(flattenedDatagram, flattenedLength, &traceContext))
    {
        memset(&sendResult, 0, sizeof(sendResult));
        decision = TryHandleBufferedInitialRewrite(
            &operation,
            &flattenedDatagram,
            flattenedLength,
            &traceContext,
            &sendResult);
        if (decision == UDP_SEND_DECISION_BUFFERED)
        {
            if (lpNumberOfBytesSent)
            {
                *lpNumberOfBytesSent = (DWORD)flattenedLength;
            }

            return 0;
        }

        if (decision == UDP_SEND_DECISION_SENT_INTERNAL)
        {
            if (flattenedDatagram)
            {
                free(flattenedDatagram);
            }

            if (lpNumberOfBytesSent && sendResult.result != SOCKET_ERROR)
            {
                *lpNumberOfBytesSent = sendResult.bytesSent;
            }

            if (sendResult.result == SOCKET_ERROR && sendResult.lastError != 0)
            {
                WSASetLastError(sendResult.lastError);
            }

            return sendResult.result;
        }
    }

    result = SendDatagramWithOperation(&operation, flattenedDatagram, flattenedLength, &sendResult);
    if (lpNumberOfBytesSent && result != SOCKET_ERROR)
    {
        *lpNumberOfBytesSent = sendResult.bytesSent;
    }

    free(flattenedDatagram);
    if (result == SOCKET_ERROR && sendResult.lastError != 0)
    {
        WSASetLastError(sendResult.lastError);
    }

    return result;
}

static int WINAPI Hooked_sendto(
    SOCKET s,
    const char* buf,
    int len,
    int flags,
    const struct sockaddr* to,
    int tolen)
{
    unsigned char* mutableDatagram;
    UDP_SEND_OPERATION operation;
    UDP_SEND_RESULT sendResult;
    UDP_SEND_DECISION decision;
    UDP_SEND_TARGET target;
    UDP_TRACE_CONTEXT traceContext;
    int result;

    RegisterHookHit(&g_sendtoHitCount);

    if (!g_pfnOriginalSendto)
    {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    if (!ResolveSendTarget(s, to, tolen, &target) ||
        GetSendTargetPort(&target) != QUIC_TARGET_UDP_PORT)
    {
        return g_pfnOriginalSendto(s, buf, len, flags, to, tolen);
    }

    if (!buf || len <= 0)
    {
        return g_pfnOriginalSendto(s, buf, len, flags, to, tolen);
    }

    mutableDatagram = (unsigned char*)malloc((SIZE_T)len);
    if (!mutableDatagram)
    {
        return g_pfnOriginalSendto(s, buf, len, flags, to, tolen);
    }

    memcpy(mutableDatagram, buf, (SIZE_T)len);
    traceContext.target = &target;
    traceContext.datagram = mutableDatagram;
    traceContext.datagramLength = (SIZE_T)len;
    operation.method = UDP_SEND_METHOD_SENDTO;
    operation.socketHandle = s;
    operation.flags = (DWORD)flags;
    operation.target = target;
    if (!TryRewriteDatagramInPlace(mutableDatagram, (SIZE_T)len, &traceContext))
    {
        memset(&sendResult, 0, sizeof(sendResult));
        decision = TryHandleBufferedInitialRewrite(
            &operation,
            &mutableDatagram,
            (SIZE_T)len,
            &traceContext,
            &sendResult);
        if (decision == UDP_SEND_DECISION_BUFFERED)
        {
            return len;
        }

        if (decision == UDP_SEND_DECISION_SENT_INTERNAL)
        {
            if (mutableDatagram)
            {
                free(mutableDatagram);
            }

            if (sendResult.result == SOCKET_ERROR && sendResult.lastError != 0)
            {
                WSASetLastError(sendResult.lastError);
            }

            return sendResult.result;
        }
    }

    result = SendDatagramWithOperation(&operation, mutableDatagram, (SIZE_T)len, &sendResult);
    free(mutableDatagram);
    if (result == SOCKET_ERROR && sendResult.lastError != 0)
    {
        WSASetLastError(sendResult.lastError);
    }

    return result;
}

static int WSAAPI Hooked_WSAIoctl(
    SOCKET s,
    DWORD dwIoControlCode,
    LPVOID lpvInBuffer,
    DWORD cbInBuffer,
    LPVOID lpvOutBuffer,
    DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    int result;
    LPFN_WSASENDMSG* returnedFunction = NULL;
    LONG hookCount = 0;

    if (!g_pfnOriginalWSAIoctl)
    {
        WSASetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    result = g_pfnOriginalWSAIoctl(
        s,
        dwIoControlCode,
        lpvInBuffer,
        cbInBuffer,
        lpvOutBuffer,
        cbOutBuffer,
        lpcbBytesReturned,
        lpOverlapped,
        lpCompletionRoutine);

    if (result == 0 &&
        dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER &&
        lpvInBuffer &&
        cbInBuffer >= sizeof(GUID) &&
        lpvOutBuffer &&
        cbOutBuffer >= sizeof(LPFN_WSASENDMSG) &&
        memcmp(lpvInBuffer, &g_WsaIdWSASendMsg, sizeof(GUID)) == 0)
    {
        returnedFunction = (LPFN_WSASENDMSG*)lpvOutBuffer;

        if (*returnedFunction && !g_pfnOriginalWSASendMsg)
        {
            g_pfnOriginalWSASendMsg = *returnedFunction;
        }

        if (*returnedFunction != (LPFN_WSASENDMSG)&Hooked_WSASendMsg)
        {
            *returnedFunction = (LPFN_WSASENDMSG)&Hooked_WSASendMsg;
            hookCount = RegisterHookHit(&g_WSASendMsgExtensionHookCount);
            if (ShouldLogHookSample(hookCount))
            {
                LogMessage(
                    "[+] Intercepted WSASendMsg extension pointer via WSAIoctl (sample #%ld)",
                    hookCount);
            }
        }
    }

    return result;
}

BOOL UdpHooks_Init(void)
{
    HMODULE hostModule;
    DWORD attempt;
    DWORD hookIndex;
    DWORD installedCount = 0;
    char hostModulePath[MAX_PATH];
    char modulePath[MAX_PATH];

    if (!InitializeCryptoProviders())
    {
        return FALSE;
    }

    g_sendHitCount = 0;
    g_WSASendToHitCount = 0;
    g_WSASendHitCount = 0;
    g_sendtoHitCount = 0;
    g_WSASendMsgHitCount = 0;
    g_WSASendMsgExtensionHookCount = 0;
    g_AsyncWsasendPassthroughCount = 0;
    g_AsyncWsasendtoPassthroughCount = 0;
    g_AsyncWsasendmsgPassthroughCount = 0;
    g_ShortHeaderPassthroughCount = 0;
    g_UnsupportedVersionPassthroughCount = 0;
    g_NonInitialPassthroughCount = 0;
    g_RetryPassthroughCount = 0;
    g_ParseFailureCount = 0;
    g_NoRewriteCount = 0;
    g_RewriteSuccessCount = 0;
    if (!g_PendingInitialLockInitialized)
    {
        InitializeCriticalSection(&g_PendingInitialLock);
        g_PendingInitialLockInitialized = TRUE;
    }

    if (g_PendingInitialLockInitialized)
    {
        DWORD slotIndex;

        EnterCriticalSection(&g_PendingInitialLock);
        for (slotIndex = 0; slotIndex < QUIC_PENDING_INITIAL_SLOT_COUNT; ++slotIndex)
        {
            ResetPendingInitialSlot(&g_PendingInitialSlots[slotIndex]);
        }
        LeaveCriticalSection(&g_PendingInitialLock);
    }

    g_pfnOriginalSend = NULL;
    g_pfnOriginalWSASendTo = NULL;
    g_pfnOriginalWSASend = NULL;
    g_pfnOriginalSendto = NULL;
    g_pfnOriginalWSASendMsg = NULL;
    g_pfnOriginalWSAIoctl = NULL;

    for (hookIndex = 0;
         hookIndex < sizeof(g_IatHookSlots) / sizeof(g_IatHookSlots[0]);
         ++hookIndex)
    {
        g_IatHookSlots[hookIndex].config = &g_IatHookConfigs[hookIndex];
        ResetIatHookSlot(&g_IatHookSlots[hookIndex]);
        g_IatHookSlots[hookIndex].config = &g_IatHookConfigs[hookIndex];
    }

    g_hWs2Module = NULL;
    g_Ws2LoadedByThisModule = FALSE;

    for (attempt = 0; attempt < HOOK_INIT_RETRY_COUNT; ++attempt)
    {
        g_hWs2Module = GetModuleHandleA("ws2_32.dll");
        if (!g_hWs2Module)
        {
            g_hWs2Module = LoadLibraryA("ws2_32.dll");
            if (g_hWs2Module)
            {
                g_Ws2LoadedByThisModule = TRUE;
            }
        }

        if (g_hWs2Module)
        {
            break;
        }

        Sleep(HOOK_INIT_RETRY_DELAY_MS);
    }

    if (!g_hWs2Module)
    {
        LogMessage("[!] Failed to resolve ws2_32.dll for IAT hook installation");
        ReleaseCryptoProviders();
        return FALSE;
    }

    modulePath[0] = '\0';
    GetModuleFileNameA(g_hWs2Module, modulePath, sizeof(modulePath));
    LogMessage("[+] Found Winsock module for IAT hooks: %s", modulePath);

    hostModule = GetModuleHandleA(NULL);
    if (!hostModule)
    {
        LogMessage("[!] Failed to resolve host module for IAT hook installation");
        UdpHooks_Cleanup();
        return FALSE;
    }

    hostModulePath[0] = '\0';
    GetModuleFileNameA(hostModule, hostModulePath, sizeof(hostModulePath));
    LogMessage("[+] Installing Winsock IAT hooks in host module: %s", hostModulePath);

    if (!InstallIatHooks(hostModule, &installedCount))
    {
        UdpHooks_Cleanup();
        return FALSE;
    }

    if (installedCount == 0)
    {
        LogMessage("[!] No IAT hooks were installed");
        UdpHooks_Cleanup();
        return FALSE;
    }

    LogMessage("[+] UDP hooks initialized successfully via IAT patching (%lu hook(s))", installedCount);
    return TRUE;
}

void UdpHooks_Cleanup(void)
{
    DWORD hookIndex;

    for (hookIndex = 0;
         hookIndex < sizeof(g_IatHookSlots) / sizeof(g_IatHookSlots[0]);
         ++hookIndex)
    {
        IAT_HOOK_SLOT* slot = &g_IatHookSlots[hookIndex];

        if (slot->installed && slot->iatEntry)
        {
            DWORD oldProtect;

            if (VirtualProtect(
                    slot->iatEntry,
                    sizeof(*slot->iatEntry),
                    PAGE_READWRITE,
                    &oldProtect))
            {
                *slot->iatEntry = slot->originalValue;
                VirtualProtect(slot->iatEntry, sizeof(*slot->iatEntry), oldProtect, &oldProtect);
            }
            else
            {
                LogMessage(
                    "[!] Failed to restore IAT entry for %s: %lu",
                    slot->config ? slot->config->label : "unknown",
                    GetLastError());
            }

            LogMessage("[*] Restored IAT entry for %s", slot->config ? slot->config->label : "unknown");
        }

        if (slot->config && slot->config->originalStorage)
        {
            *slot->config->originalStorage = NULL;
        }

        ResetIatHookSlot(slot);
        slot->config = &g_IatHookConfigs[hookIndex];
    }

    if (g_hWs2Module && g_Ws2LoadedByThisModule)
    {
        FreeLibrary(g_hWs2Module);
    }

    g_hWs2Module = NULL;
    g_Ws2LoadedByThisModule = FALSE;
    g_pfnOriginalSend = NULL;
    g_pfnOriginalWSASendTo = NULL;
    g_pfnOriginalWSASend = NULL;
    g_pfnOriginalSendto = NULL;
    g_pfnOriginalWSASendMsg = NULL;
    g_pfnOriginalWSAIoctl = NULL;
    if (g_PendingInitialLockInitialized)
    {
        DWORD slotIndex;

        EnterCriticalSection(&g_PendingInitialLock);
        for (slotIndex = 0; slotIndex < QUIC_PENDING_INITIAL_SLOT_COUNT; ++slotIndex)
        {
            ResetPendingInitialSlot(&g_PendingInitialSlots[slotIndex]);
        }
        LeaveCriticalSection(&g_PendingInitialLock);
        DeleteCriticalSection(&g_PendingInitialLock);
        g_PendingInitialLockInitialized = FALSE;
    }

    ReleaseCryptoProviders();
}

#ifdef __cplusplus
}
#endif
