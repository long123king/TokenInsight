#include "TokenSyscallProxy.h"

bool
CTokenSyscallProxy::Initialize()
{
    s_PfnRtlNtStatusToDosError = reinterpret_cast<PfnRtlNtStatusToDosError>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "RtlNtStatusToDosError"));

    s_PfnNtOpenProcessTokenEx = reinterpret_cast<PfnNtOpenProcessTokenEx>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtOpenProcessTokenEx"));

    s_PfnNtOpenThreadTokenEx = reinterpret_cast<PfnNtOpenThreadTokenEx>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtOpenThreadTokenEx"));

    s_PfnNtQueryInformationToken = reinterpret_cast<PfnNtQueryInformationToken>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtQueryInformationToken"));

    s_PfnRtlConvertSidToUnicodeString = reinterpret_cast<PfnRtlConvertSidToUnicodeString>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "RtlConvertSidToUnicodeString"));

    s_PfnNtAdjustGroupsToken = reinterpret_cast<PfnNtAdjustGroupsToken>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtAdjustGroupsToken"));

    s_PfnNtAdjustPrivilegesToken = reinterpret_cast<PfnNtAdjustPrivilegesToken>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtAdjustPrivilegesToken"));

    s_PfnRtlCheckTokenMembershipEx = reinterpret_cast<PfnRtlCheckTokenMembershipEx>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "RtlCheckTokenMembershipEx"));

    s_PfnNtFilterToken = reinterpret_cast<PfnNtFilterToken>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtFilterToken"));

    s_PfnNtCreateLowBoxToken = reinterpret_cast<PfnNtCreateLowBoxToken>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtCreateLowBoxToken"));

    s_PfnNtSetInformationToken = reinterpret_cast<PfnNtSetInformationToken>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtSetInformationToken"));

    s_PfnNtDuplicateToken = reinterpret_cast<PfnNtDuplicateToken>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtDuplicateToken"));

    s_PfnNtCreateToken = reinterpret_cast<PfnNtCreateToken>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtCreateToken"));

    s_PfnNtImpersonateAnonymousToken = reinterpret_cast<PfnNtImpersonateAnonymousToken>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtImpersonateAnonymousToken"));

    s_PfnRtlSidHashInitialize = reinterpret_cast<PfnRtlSidHashInitialize>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "RtlSidHashInitialize"));

    s_PfnNtDuplicateObject = reinterpret_cast<PfnNtDuplicateObject>(
        s_ProcAddressResolver.ResolveProcAddress("ntdll", "NtDuplicateObject"));

    return true;
}

template<typename Func, typename...ArgT>
static
bool
CTokenSyscallProxy::TokenSyscallWrapper(
    __in Func* func,
    ArgT...args
)
{
    static bool s_inited = Initialize();
    if (!s_inited || !func || !*func)
        return false;

    NTSTATUS status = (*func)(args...);

    if (0 <= status)
        return true;
    else
        cerr
        << "Fail to invoke "
        << typeid(*func).name()
        << ", Last Error is "
        << hex
        << s_PfnRtlNtStatusToDosError(status)
        << "("
        << status
        << ")"
        << endl;

    return false;
}

bool
CTokenSyscallProxy::NtOpenProcessToken(
    __in     HANDLE              processHandle,
    __in     DWORD               desiredAccess,
    __out    PHANDLE             tokenHandle
    )
{
    return NtOpenProcessTokenEx(processHandle, desiredAccess, 0, tokenHandle);
}

bool 
CTokenSyscallProxy::NtOpenProcessTokenEx(
    __in    HANDLE               processHandle,
    __in    DWORD                desiredAccess,
    __in    DWORD                handleAttributes,
    __out   PHANDLE              tokenHandle
    )
{
    return TokenSyscallWrapper<decltype(s_PfnNtOpenProcessTokenEx)>(
        &s_PfnNtOpenProcessTokenEx,
        processHandle, desiredAccess, handleAttributes, tokenHandle);
}

bool
CTokenSyscallProxy::NtOpenThreadToken(
    __in    HANDLE               threadHandle,
    __in    DWORD                desiredAccess,
    __in    BOOL                 openAsSelf,
    __out   PHANDLE              tokenHandle
    )
{
    return NtOpenThreadTokenEx(threadHandle, desiredAccess, openAsSelf, 0, tokenHandle);
}

bool
CTokenSyscallProxy::NtOpenThreadTokenEx(
    __in    HANDLE               threadHandle,
    __in    DWORD                desiredAccess,
    __in    BOOL                 openAsSelf,
    __in    DWORD                handleAttributes,
    __out   PHANDLE              tokenHandle
    )
{
    return TokenSyscallWrapper<decltype(s_PfnNtOpenThreadTokenEx)>(
        &s_PfnNtOpenThreadTokenEx,
        threadHandle, desiredAccess, openAsSelf, handleAttributes, tokenHandle);
}

bool
CTokenSyscallProxy::NtQueryInformationToken(
    __in    HANDLE                    tokenHandle,
    __in    TOKEN_INFORMATION_CLASS   tokenInformationClass,
    __out   PVOID                     tokenInformation,
    __in    DWORD                     tokenInformationLength,
    __out   PDWORD                    returnLength
    )
{
    return TokenSyscallWrapper<decltype(s_PfnNtQueryInformationToken)>(
        &s_PfnNtQueryInformationToken,
        tokenHandle, tokenInformationClass, tokenInformation, tokenInformationLength, returnLength);
}

bool
CTokenSyscallProxy::RtlConvertSidToUnicodeString(
    __out   PUNICODE_STRING           unicodeString,
    __in    PSID                      sid,
    __in    BOOL                      allocateDestinationString
    )
{
    return TokenSyscallWrapper<decltype(s_PfnRtlConvertSidToUnicodeString)>(
        &s_PfnRtlConvertSidToUnicodeString,
        unicodeString, sid, allocateDestinationString);
}

bool 
CTokenSyscallProxy::NtAdjustGroupsToken(
    __in    HANDLE                    tokenHandle,
    __in    BOOL                      resetToDefault,
    __in    PTOKEN_GROUPS             newState,
    __in    DWORD                     bufferLength,
    __out   PTOKEN_GROUPS             previousState,
    __out   PDWORD                    returnLength
    )
{
    return TokenSyscallWrapper<decltype(s_PfnNtAdjustGroupsToken)>(
        &s_PfnNtAdjustGroupsToken,
        tokenHandle, resetToDefault, newState, bufferLength, previousState, returnLength);
}

bool
CTokenSyscallProxy::NtAdjustPrivilegesToken(
    __in    HANDLE                    tokenHandle,
    __in    BOOL                      disableAllPrivileges,
    __in    PTOKEN_PRIVILEGES         newState,
    __in    DWORD                     bufferLength,
    __out   PTOKEN_PRIVILEGES         previousState,
    __out   PDWORD                    returnLength
    )
{
    return TokenSyscallWrapper<decltype(s_PfnNtAdjustPrivilegesToken)>(
        &s_PfnNtAdjustPrivilegesToken,
        tokenHandle, disableAllPrivileges, newState, bufferLength, previousState, returnLength);
}

bool
CTokenSyscallProxy::RtlCheckTokenMembership(
    __in    HANDLE                   tokenHandle,
    __in    PSID                     sidToCheck,
    __out   PBOOL                    isMember
    )
{
    return RtlCheckTokenMembershipEx(tokenHandle, sidToCheck, 0, isMember);
}

bool
CTokenSyscallProxy::RtlCheckTokenMembershipEx(
    __in     HANDLE                  tokenHandle,
    __in     PSID                    sidToCheck,
    __in     DWORD                   flags,
    __out    PBOOL                   isMember
    )
{
    return TokenSyscallWrapper<decltype(s_PfnRtlCheckTokenMembershipEx)>(
        &s_PfnRtlCheckTokenMembershipEx,
        tokenHandle, sidToCheck, flags, isMember);
}

bool
CTokenSyscallProxy::NtFilterToken(
    __in    HANDLE                   existingTokenHandle,
    __in    DWORD                    flags,
    __in    PTOKEN_GROUPS            sidsToDisable,
    __in    PTOKEN_PRIVILEGES        privilegesToDelete,
    __in    PTOKEN_GROUPS            restrictedSids,
    __out   PHANDLE                  newTokenHandle
    )
{
    return TokenSyscallWrapper<decltype(s_PfnNtFilterToken)>(
        &s_PfnNtFilterToken,
        existingTokenHandle, flags, sidsToDisable, privilegesToDelete, restrictedSids, newTokenHandle);
}

bool
CTokenSyscallProxy::NtCreateLowBoxToken(
    __out   PHANDLE                  token,
    __in    HANDLE                   originalHandle,
    __in    ACCESS_MASK              access,
    __in    POBJECT_ATTRIBUTES       objectAttribute,
    __in    PSID                     appContainerSid,
    __in    DWORD                    capabilityCount,
    __in    PSID_AND_ATTRIBUTES      capabilities,
    __in    DWORD                    handleCount,
    __in    PHANDLE                  handles
    )
{
    return TokenSyscallWrapper<decltype(s_PfnNtCreateLowBoxToken)>(
        &s_PfnNtCreateLowBoxToken,
        token, originalHandle, access, objectAttribute, appContainerSid, capabilityCount, capabilities, handleCount, handles
        );
}

bool
CTokenSyscallProxy::NtDuplicateToken(
    __in    HANDLE                    existingTokenHandle,
    __in    DWORD                     desiredAccess,
    __in    POBJECT_ATTRIBUTES        objectAttributes,
    __in    BOOL                      effectiveOnly,
    __in    TOKEN_TYPE                tokenType,
    __out   PHANDLE                   newTokenHandle
    )
{
    return TokenSyscallWrapper<decltype(s_PfnNtDuplicateToken)>(
        &s_PfnNtDuplicateToken,
        existingTokenHandle, desiredAccess, objectAttributes, effectiveOnly, tokenType, newTokenHandle);
}

bool
CTokenSyscallProxy::NtSetInformationThread(
    __in    HANDLE                    threadHandle,
    __in    THREADINFOCLASS           threadInformationClass, // case ThreadImpersonationToken:
    __in    PVOID                     threadInformation,
    __in    DWORD                     threadInformationLength
    )
{
    return TokenSyscallWrapper<decltype(s_PfnNtSetInformationThread)>(
        &s_PfnNtSetInformationThread,
        threadHandle, threadInformationClass, threadInformation, threadInformationLength);
}

bool
CTokenSyscallProxy::NtSetInformationToken(
    __in    HANDLE                    tokenHandle,
    __in    TOKEN_INFORMATION_CLASS   tokenInformationClass,
    __in    PVOID                     tokenInformation,
    __in    DWORD                     tokenInformationLength
    )
{
    return TokenSyscallWrapper<decltype(s_PfnNtSetInformationToken)>(
        &s_PfnNtSetInformationToken,
        tokenHandle, tokenInformationClass, tokenInformation, tokenInformationLength);
}

bool
CTokenSyscallProxy::RtlSidHashInitialize(
    __in    PSID_AND_ATTRIBUTES        groups,
    __in    size_t                     groupsCount,
    __inout PSID_AND_ATTRIBUTES_HASH   hashBuffer
    )
{
    return TokenSyscallWrapper<decltype(s_PfnRtlSidHashInitialize)>(
        &s_PfnRtlSidHashInitialize,
        groups, groupsCount, hashBuffer);
}

bool CTokenSyscallProxy::NtDuplicateObject(
    __in      HANDLE      SourceProcessHandle,
    __in      HANDLE      SourceHandle,
    __in      HANDLE      TargetProcessHandle,
    __out     PHANDLE     TargetHandle,
    __in      ACCESS_MASK DesiredAccess,
    __in      ULONG       HandleAttributes,
    __in      ULONG       Options)
{
    return TokenSyscallWrapper<decltype(s_PfnNtDuplicateObject)>(
        &s_PfnNtDuplicateObject,
        SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
}

CProcAddressResolver                   CTokenSyscallProxy::s_ProcAddressResolver;

PfnRtlNtStatusToDosError               CTokenSyscallProxy::s_PfnRtlNtStatusToDosError = nullptr;
PfnNtOpenProcessToken                  CTokenSyscallProxy::s_PfnNtOpenProcessToken = nullptr;
PfnNtOpenProcessTokenEx                CTokenSyscallProxy::s_PfnNtOpenProcessTokenEx = nullptr;
PfnNtOpenThreadToken                   CTokenSyscallProxy::s_PfnNtOpenThreadToken = nullptr;
PfnNtOpenThreadTokenEx                 CTokenSyscallProxy::s_PfnNtOpenThreadTokenEx = nullptr;
PfnNtQueryInformationToken             CTokenSyscallProxy::s_PfnNtQueryInformationToken = nullptr;
PfnRtlConvertSidToUnicodeString        CTokenSyscallProxy::s_PfnRtlConvertSidToUnicodeString = nullptr;
PfnNtAdjustGroupsToken                 CTokenSyscallProxy::s_PfnNtAdjustGroupsToken = nullptr;
PfnNtAdjustPrivilegesToken             CTokenSyscallProxy::s_PfnNtAdjustPrivilegesToken = nullptr;
PfnRtlCheckTokenMembershipEx           CTokenSyscallProxy::s_PfnRtlCheckTokenMembershipEx = nullptr;
PfnNtFilterToken                       CTokenSyscallProxy::s_PfnNtFilterToken = nullptr;
PfnNtCreateLowBoxToken                 CTokenSyscallProxy::s_PfnNtCreateLowBoxToken = nullptr;
PfnNtDuplicateToken                    CTokenSyscallProxy::s_PfnNtDuplicateToken = nullptr;
PfnNtSetInformationThread              CTokenSyscallProxy::s_PfnNtSetInformationThread = nullptr;
PfnNtSetInformationToken               CTokenSyscallProxy::s_PfnNtSetInformationToken = nullptr;
PfnNtCreateToken                       CTokenSyscallProxy::s_PfnNtCreateToken = nullptr;
PfnNtImpersonateAnonymousToken         CTokenSyscallProxy::s_PfnNtImpersonateAnonymousToken = nullptr;
PfnRtlSidHashInitialize                CTokenSyscallProxy::s_PfnRtlSidHashInitialize = nullptr;
PfnNtDuplicateObject                   CTokenSyscallProxy::s_PfnNtDuplicateObject = nullptr;

