#pragma once

#include <stddef.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WARPS_VERSION
#define WARPS_VERSION "unknown"
#endif

BOOL Config_Load(void);
BOOL Config_CopySNI(char* buffer, size_t bufferLen);

#ifdef __cplusplus
}
#endif
