#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

BOOL Hooks_InitStaticHostnamePatches(void);
BOOL Hooks_InitCryptoBufferNew(void);
void Hooks_InitSslSetSni(void);
void Hooks_Cleanup(void);
BOOL IsClientHelloBuffer(const unsigned char* data, SIZE_T len);
unsigned char* ModifyClientHelloSNI(unsigned char* data, SIZE_T* len, const char* newSNI);

BOOL TryExtractObservedSni(
    const unsigned char* data,
    SIZE_T len,
    char* sni,
    size_t sniCapacity,
    const char** sourceKind);

SIZE_T FindSNIExtension(const unsigned char* clientHello, SIZE_T helloLen, 
                        WORD* outExtensionLen);

BOOL Hooks_UpdateStaticSNI(const char* newSni);
BOOL Hooks_AreStaticHostnamePatchesActive(void);

#ifdef __cplusplus
}
#endif
