#pragma once
#include <Windows.h>
#include <cstdint>

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

using PfnRtlNtStatusToDosError = 
    ULONG (WINAPI*)(
    __in  NTSTATUS      Status
    );

using PfnNtOpenProcessToken =
    NTSTATUS (WINAPI*)(
    __in  HANDLE         ProcessHandle,
    __in  ACCESS_MASK    DesiredAccess,
    __out PHANDLE        TokenHandle
    );

using PfnNtOpenProcessTokenEx =
    NTSTATUS (WINAPI*)(
    __in  HANDLE         ProcessHandle,
    __in  ACCESS_MASK    DesiredAccess,
    __in  ULONG          HandleAttributes,
    __out PHANDLE        TokenHandle
    ); 

using PfnNtOpenThreadToken =
    NTSTATUS (WINAPI*)(
    __in  HANDLE         ThreadHandle,
    __in  ACCESS_MASK    DesiredAccess,
    __in  BOOLEAN        OpenAsSelf,
    __out PHANDLE        TokenHandle
    );

using PfnNtOpenThreadTokenEx =
    NTSTATUS (WINAPI*)(
    __in  HANDLE         ThreadHandle,
    __in  ACCESS_MASK    DesiredAccess,
    __in  BOOLEAN        OpenAsSelf,
    __in  ULONG          HandleAttributes,
    __out PHANDLE        TokenHandle
    );

// TokenIsAppContainer is not down to here, already processed in KernelBase.dll/GetTokenInformation.
using PfnNtQueryInformationToken =
    NTSTATUS (WINAPI*)(
    __in  HANDLE                          TokenHandle,
    __in  TOKEN_INFORMATION_CLASS         TokenInformationClass,
    __out PVOID                           TokenInformation,
    __in  ULONG                           TokenInformationLength,
    __out PULONG                          ReturnLength
    );

using PfnNtSetInformationToken =
    NTSTATUS (WINAPI*)(
    __in  HANDLE                          TokenHandle,
    __in  TOKEN_INFORMATION_CLASS         TokenInformationClass,
    __in  PVOID                           TokenInformation,
    __in  ULONG                           TokenInformationLength
    );

using PfnRtlConvertSidToUnicodeString =
    NTSTATUS (WINAPI*)(
    __out PUNICODE_STRING                 UnicodeString,
    __in  PSID                            Sid,
    __in  BOOLEAN                         AllocateDestinationString
    );

using PfnNtAdjustGroupsToken =
    NTSTATUS (WINAPI*)(
    __in  HANDLE                         TokenHandle,
    __in  BOOLEAN                        ResetToDefault,
    __in  PTOKEN_GROUPS                  NewState,
    __in  ULONG                          BufferLength,
    __out_bcount_part_opt(BufferLength, *ReturnLength) PTOKEN_GROUPS PreviousState,
    __out PULONG                         ReturnLength
    );

using PfnNtAdjustPrivilegesToken =
    NTSTATUS (WINAPI*)(
    __in      HANDLE                         TokenHandle,
    __in      BOOLEAN                        DisableAllPrivileges,
    __in_opt  PTOKEN_PRIVILEGES              NewState,
    __in      ULONG                          BufferLength,
    __out_bcount_part_opt(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
    __out_opt PULONG                         ReturnLength
    );

using PfnRtlCheckTokenMembershipEx =
    NTSTATUS (WINAPI*)(
    __in_opt HANDLE       TokenHandle,
    __in     PSID         SidToCheck,
    __in     DWORD        Flags,
    __out    PBOOL        IsMember
    );

using PfnNtFilterToken =
    NTSTATUS (WINAPI*)(
    __in     HANDLE                ExistingTokenHandle,
    __in     ULONG                 Flags,
    __in_opt PTOKEN_GROUPS         SidsToDisable,
    __in_opt PTOKEN_PRIVILEGES     PrivilegesToDelete,
    __in_opt PTOKEN_GROUPS         RestrictedSids,
    __out    PHANDLE               NewTokenHandle
    );

using PfnNtImpersonateAnonymousToken =
    NTSTATUS (WINAPI*)(
    __in    HANDLE                 ThreadHandle
    );

using PfnRtlSidHashInitialize = 
    NTSTATUS (WINAPI*)(
    __in    PSID_AND_ATTRIBUTES            Groups,
    __in    DWORD                          GroupsCount,
    __inout PSID_AND_ATTRIBUTES_HASH       HashBuffer
    );

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG32      Length;
    UINT8        _PADDING0_[0x4];
    VOID*        RootDirectory;
    struct _UNICODE_STRING* ObjectName;
    ULONG32      Attributes;
    UINT8        _PADDING1_[0x4];
    VOID*        SecurityDescriptor;
    VOID*        SecurityQualityOfService;
}OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

using PfnNtCreateToken =
    NTSTATUS (WINAPI*)(
    __out       PHANDLE              TokenHandle,
    __in        ACCESS_MASK          DesiredAccess,
    __in        POBJECT_ATTRIBUTES   ObjectAttributes,
    __in        TOKEN_TYPE           TokenType,
    __in        PLUID                AuthenticationId,
    __in        PLARGE_INTEGER       ExpirationTime,
    __in        PTOKEN_USER          TokenUser,
    __in        PTOKEN_GROUPS        TokenGroups,
    __in        PTOKEN_PRIVILEGES    TokenPrivileges,
    __in        PTOKEN_OWNER         TokenOwner,
    __in        PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,
    __in        PTOKEN_DEFAULT_DACL  TokenDefaultDacl,
    __in        PTOKEN_SOURCE        TokenSource 
    );

//##################################################
// Valid Handle Attributes are as belows:
//##################################################
#define OBJ_INHERIT                  0x00000002L
#define OBJ_PERMANENT                0x00000010L
#define OBJ_EXCLUSIVE                0x00000020L
#define OBJ_CASE_INSENSITIVE         0x00000040L
#define OBJ_OPENIF                   0x00000080L
#define OBJ_OPENLINK                 0x00000100L
#define OBJ_KERNEL_HANDLE            0x00000200L
#define OBJ_VALID_ATTRIBUTES         0x000003F2L

using PfnNtDuplicateToken =
    NTSTATUS (WINAPI*)(
    __in    HANDLE                   ExistingTokenHandle,
    __in    ACCESS_MASK              DesiredAccess,
    __in    POBJECT_ATTRIBUTES       ObjectAttributes,
    __in    BOOLEAN                  EffectiveOnly,
    __in    TOKEN_TYPE               TokenType,
    __out   PHANDLE                  NewTokenHandle
    );

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    MaxThreadInfoClass
} THREADINFOCLASS;

using PfnNtSetInformationThread =
    NTSTATUS (WINAPI*)(
    __in    HANDLE                ThreadHandle,
    __in    THREADINFOCLASS       ThreadInformationClass, // case ThreadImpersonationToken:
    __in_bcount(ThreadInformationLength) PVOID ThreadInformation,
    __in    ULONG                 ThreadInformationLength
    );

using PfnNtCreateLowBoxToken =
    NTSTATUS (WINAPI*)(
    __out PHANDLE                  token,
    __in HANDLE                    originalHandle,
    __in ACCESS_MASK               access,
    __in POBJECT_ATTRIBUTES        objectAttribute,
    __in PSID                      appContainerSid,
    __in DWORD                     capabilityCount,
    __in PSID_AND_ATTRIBUTES       capabilities,
    __in DWORD                     handleCount,
    __in PHANDLE                   handles
    );

enum IntegrityLevel
{
    IntegrityLevel_Untrusted = 0,
    IntegrityLevel_Low,
    IntegrityLevel_Medium,
    IntegrityLevel_High,
    IntegrityLevel_System
};

typedef struct _SID2 {
   BYTE  Revision;
   BYTE  SubAuthorityCount;
   SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
   DWORD SubAuthority[2];
} SID2, *PISID2;

using PfnNtDuplicateObject = 
NTSTATUS (WINAPI*)(
    __in      HANDLE      SourceProcessHandle,
    __in      HANDLE      SourceHandle,
    __in      HANDLE      TargetProcessHandle,
    __out     PHANDLE     TargetHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in      ULONG       HandleAttributes,
    __in      ULONG       Options
    );
