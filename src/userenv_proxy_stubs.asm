option casemap:none

EXTERN g_UserenvForwarders:QWORD

.code

USERENV_EXPORT MACRO slot:req, exportName:req
PUBLIC exportName
exportName PROC
    jmp QWORD PTR [g_UserenvForwarders + (slot * 8)]
exportName ENDP
ENDM

USERENV_EXPORT 0, __ord_104
USERENV_EXPORT 1, RsopLoggingEnabled
USERENV_EXPORT 2, AreThereVisibleLogoffScripts
USERENV_EXPORT 3, AreThereVisibleShutdownScripts
USERENV_EXPORT 4, CreateAppContainerProfile
USERENV_EXPORT 5, CreateEnvironmentBlock
USERENV_EXPORT 6, CreateProfile
USERENV_EXPORT 7, DeleteAppContainerProfile
USERENV_EXPORT 8, DeleteProfileA
USERENV_EXPORT 9, DeleteProfileW
USERENV_EXPORT 10, DeriveAppContainerSidFromAppContainerName
USERENV_EXPORT 11, DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName
USERENV_EXPORT 12, DestroyEnvironmentBlock
USERENV_EXPORT 13, DllCanUnloadNow
USERENV_EXPORT 14, DllGetClassObject
USERENV_EXPORT 15, DllRegisterServer
USERENV_EXPORT 16, DllUnregisterServer
USERENV_EXPORT 17, EnterCriticalPolicySection
USERENV_EXPORT 18, __ord_122
USERENV_EXPORT 19, ExpandEnvironmentStringsForUserA
USERENV_EXPORT 20, ExpandEnvironmentStringsForUserW
USERENV_EXPORT 21, ForceSyncFgPolicy
USERENV_EXPORT 22, FreeGPOListA
USERENV_EXPORT 23, FreeGPOListW
USERENV_EXPORT 24, GenerateGPNotification
USERENV_EXPORT 25, GetAllUsersProfileDirectoryA
USERENV_EXPORT 26, GetAllUsersProfileDirectoryW
USERENV_EXPORT 27, GetAppContainerFolderPath
USERENV_EXPORT 28, GetAppContainerRegistryLocation
USERENV_EXPORT 29, GetAppliedGPOListA
USERENV_EXPORT 30, GetAppliedGPOListW
USERENV_EXPORT 31, __ord_135
USERENV_EXPORT 32, GetDefaultUserProfileDirectoryA
USERENV_EXPORT 33, __ord_137
USERENV_EXPORT 34, GetDefaultUserProfileDirectoryW
USERENV_EXPORT 35, __ord_139
USERENV_EXPORT 36, GetGPOListA
USERENV_EXPORT 37, GetGPOListW
USERENV_EXPORT 38, GetNextFgPolicyRefreshInfo
USERENV_EXPORT 39, GetPreviousFgPolicyRefreshInfo
USERENV_EXPORT 40, GetProfileType
USERENV_EXPORT 41, GetProfilesDirectoryA
USERENV_EXPORT 42, GetProfilesDirectoryW
USERENV_EXPORT 43, GetUserProfileDirectoryA
USERENV_EXPORT 44, GetUserProfileDirectoryW
USERENV_EXPORT 45, HasPolicyForegroundProcessingCompleted
USERENV_EXPORT 46, LeaveCriticalPolicySection
USERENV_EXPORT 47, LoadProfileExtender
USERENV_EXPORT 48, LoadUserProfileA
USERENV_EXPORT 49, LoadUserProfileW
USERENV_EXPORT 50, ProcessGroupPolicyCompleted
USERENV_EXPORT 51, ProcessGroupPolicyCompletedEx
USERENV_EXPORT 52, RefreshPolicy
USERENV_EXPORT 53, RefreshPolicyEx
USERENV_EXPORT 54, RegisterGPNotification
USERENV_EXPORT 55, RsopAccessCheckByType
USERENV_EXPORT 56, RsopFileAccessCheck
USERENV_EXPORT 57, RsopResetPolicySettingStatus
USERENV_EXPORT 58, RsopSetPolicySettingStatus
USERENV_EXPORT 59, UnloadProfileExtender
USERENV_EXPORT 60, UnloadUserProfile
USERENV_EXPORT 61, UnregisterGPNotification
USERENV_EXPORT 62, WaitForMachinePolicyForegroundProcessing
USERENV_EXPORT 63, WaitForUserPolicyForegroundProcessing
USERENV_EXPORT 64, __ord_175
USERENV_EXPORT 65, __ord_202
USERENV_EXPORT 66, __ord_203
USERENV_EXPORT 67, __ord_206
USERENV_EXPORT 68, __ord_207
USERENV_EXPORT 69, __ord_208
USERENV_EXPORT 70, __ord_209
USERENV_EXPORT 71, __ord_210
USERENV_EXPORT 72, __ord_211
USERENV_EXPORT 73, __ord_212
USERENV_EXPORT 74, __ord_213
USERENV_EXPORT 75, __ord_214
USERENV_EXPORT 76, __ord_217
USERENV_EXPORT 77, __ord_218
USERENV_EXPORT 78, __ord_219

END
