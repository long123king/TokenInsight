#pragma once

using namespace std;

#include "TypeDeclarations.h"
#include "ProcAddressResolver.h"

class CTokenSyscallProxy
{
public:
    static
    bool
    Initialize();

    template<typename Func, typename...ArgT>
    static
    bool
    TokenSyscallWrapper(
        __in Func* func,
        ArgT...args
        );

    static
    bool
    NtOpenProcessToken(
        __in     HANDLE              processHandle,
        __in     DWORD               desiredAccess,
        __out    PHANDLE             tokenHandle
        );

    static
    bool 
    NtOpenProcessTokenEx(
        __in    HANDLE               processHandle,
        __in    DWORD                desiredAccess,
        __in    DWORD                handleAttributes,
        __out   PHANDLE              tokenHandle
        );

    static
    bool
    NtOpenThreadToken(
        __in    HANDLE               threadHandle,
        __in    DWORD                desiredAccess,
        __in    BOOL                 openAsSelf,
        __out   PHANDLE              tokenHandle
        );

    static
    bool
    NtOpenThreadTokenEx(
        __in    HANDLE               threadHandle,
        __in    DWORD                desiredAccess,
        __in    BOOL                 openAsSelf,
        __in    DWORD                handleAttributes,
        __out   PHANDLE              tokenHandle
        );

    static
    bool
    NtQueryInformationToken(
        __in    HANDLE                    tokenHandle,
        __in    TOKEN_INFORMATION_CLASS   tokenInformationClass,
        __out   PVOID                     tokenInformation,
        __in    DWORD                     tokenInformationLength,
        __out   PDWORD                    returnLength
        );

    static
    bool
    RtlConvertSidToUnicodeString(
        __out   PUNICODE_STRING           unicodeString,
        __in    PSID                      sid,
        __in    BOOL                      allocateDestinationString
        );

    static
    bool 
    NtAdjustGroupsToken(
        __in    HANDLE                    tokenHandle,
        __in    BOOL                      resetToDefault,
        __in    PTOKEN_GROUPS             newState,
        __in    DWORD                     bufferLength,
        __out   PTOKEN_GROUPS             previousState,
        __out   PDWORD                    returnLength
        );

    static
    bool 
    NtAdjustPrivilegesToken(
        __in    HANDLE                    tokenHandle,
        __in    BOOL                      disableAllPrivileges,
        __in    PTOKEN_PRIVILEGES         newState,
        __in    DWORD                     bufferLength,
        __out   PTOKEN_PRIVILEGES         previousState,
        __out   PDWORD                    returnLength
        );

    static
    bool
    RtlCheckTokenMembership(
        __in    HANDLE                   tokenHandle,
        __in    PSID                     sidToCheck,
        __out   PBOOL                    isMember
        );

    static
    bool 
    RtlCheckTokenMembershipEx(
        __in     HANDLE                  tokenHandle,
        __in     PSID                    sidToCheck,
        __in     DWORD                   flags,
        __out    PBOOL                   isMember
        );

    static
    bool 
    NtFilterToken(
        __in    HANDLE                   existingTokenHandle,
        __in    DWORD                    flags,
        __in    PTOKEN_GROUPS            sidsToDisable,
        __in    PTOKEN_PRIVILEGES        privilegesToDelete,
        __in    PTOKEN_GROUPS            restrictedSids,
        __out   PHANDLE                  newTokenHandle
        );

    static
    bool
    NtCreateLowBoxToken(
        __out   PHANDLE                  token,
        __in    HANDLE                   originalHandle,
        __in    ACCESS_MASK              access,
        __in    POBJECT_ATTRIBUTES       objectAttribute,
        __in    PSID                     appContainerSid,
        __in    DWORD                    capabilityCount,
        __in    PSID_AND_ATTRIBUTES      capabilities,
        __in    DWORD                    handleCount,
        __in    PHANDLE                  handles
        );

    static
    bool
    NtDuplicateToken(
        __in    HANDLE                    existingTokenHandle,
        __in    DWORD                     desiredAccess,
        __in    POBJECT_ATTRIBUTES        objectAttributes,
        __in    BOOL                      effectiveOnly,
        __in    TOKEN_TYPE                tokenType,
        __out   PHANDLE                   newTokenHandle
        );

    static
    bool 
    NtSetInformationThread(
        __in    HANDLE                    threadHandle,
        __in    THREADINFOCLASS           threadInformationClass, // case ThreadImpersonationToken:
        __in    PVOID                     threadInformation,
        __in    DWORD                     threadInformationLength
        );

    static
    bool
    NtSetInformationToken(
        __in    HANDLE                    tokenHandle,
        __in    TOKEN_INFORMATION_CLASS   tokenInformationClass,
        __in    PVOID                     tokenInformation,
        __in    DWORD                     tokenInformationLength
        );

    static
    bool
    RtlSidHashInitialize(
        __in    PSID_AND_ATTRIBUTES        groups,
        __in    size_t                     groupsCount,
        __inout PSID_AND_ATTRIBUTES_HASH   hashBuffer
        );

    static
    bool
    NtDuplicateObject(
        __in      HANDLE      SourceProcessHandle,
        __in      HANDLE      SourceHandle,
        __in      HANDLE      TargetProcessHandle,
        __out     PHANDLE     TargetHandle,
        __in      ACCESS_MASK DesiredAccess,
        __in      ULONG       HandleAttributes,
        __in      ULONG       Options
        );

private:
    static CProcAddressResolver                    s_ProcAddressResolver;

    static PfnRtlNtStatusToDosError                s_PfnRtlNtStatusToDosError;
    static PfnNtOpenProcessToken                   s_PfnNtOpenProcessToken;    
    static PfnNtOpenProcessTokenEx                 s_PfnNtOpenProcessTokenEx;
    static PfnNtOpenThreadToken                    s_PfnNtOpenThreadToken;
    static PfnNtOpenThreadTokenEx                  s_PfnNtOpenThreadTokenEx;
    static PfnNtQueryInformationToken              s_PfnNtQueryInformationToken;
    static PfnRtlConvertSidToUnicodeString         s_PfnRtlConvertSidToUnicodeString;
    static PfnNtAdjustGroupsToken                  s_PfnNtAdjustGroupsToken;
    static PfnNtAdjustPrivilegesToken              s_PfnNtAdjustPrivilegesToken;
    static PfnRtlCheckTokenMembershipEx            s_PfnRtlCheckTokenMembershipEx;
    static PfnNtFilterToken                        s_PfnNtFilterToken;
    static PfnNtCreateLowBoxToken                  s_PfnNtCreateLowBoxToken;
    static PfnNtDuplicateToken                     s_PfnNtDuplicateToken;
    static PfnNtSetInformationThread               s_PfnNtSetInformationThread;
    static PfnNtSetInformationToken                s_PfnNtSetInformationToken;
    static PfnNtCreateToken                        s_PfnNtCreateToken;
    static PfnNtImpersonateAnonymousToken          s_PfnNtImpersonateAnonymousToken;
    static PfnRtlSidHashInitialize                 s_PfnRtlSidHashInitialize;
    static PfnNtDuplicateObject                    s_PfnNtDuplicateObject;
};

