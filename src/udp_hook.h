#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

BOOL UdpHooks_Init(void);
void UdpHooks_Cleanup(void);

#ifdef __cplusplus
}
#endif
