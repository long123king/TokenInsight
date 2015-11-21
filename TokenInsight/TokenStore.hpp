#pragma once

#include "TokenSyscallProxy.h"
#include "TokenUtility.hpp"
#include "TokenCache.hpp"

class CTokenStore
{
public:
    static
    unique_ptr<CAccessToken>
    GetCurrentProcessToken()
    {
        HANDLE process_token_handle = 0;
        if (CTokenSyscallProxy::NtOpenProcessToken(
            CEnvironmentProxy::GetCurrentProcess().Get(), TOKEN_ALL_ACCESS, &process_token_handle))
            return make_unique<CAccessToken>(process_token_handle);

        return nullptr;
    }

    static
    unique_ptr<CAccessToken>
    GetCurrentThreadToken()
    {
        HANDLE thread_token_handle = 0;
        if (CTokenSyscallProxy::NtOpenThreadToken(
            CEnvironmentProxy::GetCurrentThread().Get(), TOKEN_ALL_ACCESS, false, &thread_token_handle))
            return make_unique<CAccessToken>(thread_token_handle);

        return nullptr;
    }

    static
    unique_ptr<CAccessToken>
    GetProcessToken(
        __in HANDLE processHandle
        )
    {
        HANDLE process_token_handle = 0;
        if (CTokenSyscallProxy::NtOpenProcessToken(
            processHandle, TOKEN_ALL_ACCESS, &process_token_handle))
            return make_unique<CAccessToken>(process_token_handle);

        return nullptr;
    }

    static
    unique_ptr<CAccessToken>
    GetProcessTokenByPid
    (
        __in DWORD pid
        )
    {
        return GetProcessToken(OpenProcess(PROCESS_QUERY_INFORMATION, false, pid));        
    }

    static
    unique_ptr<CAccessToken>
    GetThreadToken(
        __in HANDLE threadHandle
        )
    {
        HANDLE thread_token_handle = 0;
        if (CTokenSyscallProxy::NtOpenThreadToken(
            threadHandle, TOKEN_ALL_ACCESS, false, &thread_token_handle))
            return make_unique<CAccessToken>(thread_token_handle);

        return nullptr;
    }

    static
    unique_ptr<CAccessToken>
    CreateRestrictedToken(
        __in    HANDLE                   token,
        __in    DWORD                    flags,
        __in    PTOKEN_GROUPS            sidsToDisable,
        __in    PTOKEN_PRIVILEGES        privilegesToDelete,
        __in    PTOKEN_GROUPS            restrictedSids
        )
    {
        HANDLE filtered_handle = INVALID_HANDLE_VALUE;
        if (!CTokenSyscallProxy::NtFilterToken(
            token,
            flags,
            sidsToDisable,
            privilegesToDelete,
            restrictedSids,
            &filtered_handle
            ))
            return nullptr;

        return make_unique<CAccessToken>(filtered_handle);
    }

    static
    unique_ptr<CAccessToken>
    CreateLowBoxToken(
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
        HANDLE lowbox_handle = INVALID_HANDLE_VALUE;
        if (!CTokenSyscallProxy::NtCreateLowBoxToken(
            &lowbox_handle,
            originalHandle,
            access,
            objectAttribute,
            appContainerSid,
            capabilityCount,
            capabilities,
            handleCount,
            handles
            ))
            return nullptr;

        return make_unique<CAccessToken>(lowbox_handle);
    }

    static
    unique_ptr<CAccessToken>
    CreateImpersonationToken(
        __in     HANDLE                         existingToken,
        __in     DWORD                          desiredAccess,
        __in     LPSECURITY_ATTRIBUTES          tokenAttributes,
        __in     SECURITY_IMPERSONATION_LEVEL   impersonationLevel,
        __in     TOKEN_TYPE                     tokenType
        )
    {
        HANDLE impersonation_handle = INVALID_HANDLE_VALUE;
        SECURITY_QUALITY_OF_SERVICE quality_of_service = {sizeof(SECURITY_QUALITY_OF_SERVICE), impersonationLevel, false, false};
        OBJECT_ATTRIBUTES object_attrs = {sizeof(OBJECT_ATTRIBUTES), 0,};
        if (tokenAttributes->bInheritHandle)
            object_attrs.Attributes &= OBJ_INHERIT;
        object_attrs.SecurityDescriptor = tokenAttributes->lpSecurityDescriptor;
        if (!CTokenSyscallProxy::NtDuplicateToken(
            existingToken,
            desiredAccess,
            &object_attrs,
            FALSE,
            tokenType,
            &impersonation_handle))
            return nullptr;

        return make_unique<CAccessToken>(impersonation_handle);
    }

    static
    unique_ptr<CAccessToken>
    CreateImpersonationToken(
        __in     HANDLE                         existingToken,
        __in     DWORD                          desiredAccess,
        __in     bool                           inheritable,
        __in     PSECURITY_DESCRIPTOR           securityDescriptor,
        __in     SECURITY_IMPERSONATION_LEVEL   impersonationLevel,
        __in     TOKEN_TYPE                     tokenType
        )
    {
        HANDLE impersonation_handle = INVALID_HANDLE_VALUE;
        SECURITY_QUALITY_OF_SERVICE quality_of_service = {sizeof(SECURITY_QUALITY_OF_SERVICE), impersonationLevel, false, false};
        OBJECT_ATTRIBUTES object_attrs = {sizeof(OBJECT_ATTRIBUTES), 0,};
        if (inheritable)
            object_attrs.Attributes &= OBJ_INHERIT;
        object_attrs.SecurityDescriptor = securityDescriptor;
        if (!CTokenSyscallProxy::NtDuplicateToken(
            existingToken,
            desiredAccess,
            &object_attrs,
            FALSE,
            tokenType,
            &impersonation_handle))
            return nullptr;

        return make_unique<CAccessToken>(impersonation_handle);
    }

    static
    bool
    IsTokenRestricted(
        __in    HANDLE                           token
        )
    {
        CTokenRestrictedSids restricted_sids(token);
        return restricted_sids.Instance() && restricted_sids.Instance()->GroupCount > 0;
    }

    static
    bool
    SetImpersonationToken(
        __in    HANDLE                          threadHandle,
        __in    HANDLE                          tokenHandle
        )
    {
        return CTokenSyscallProxy::NtSetInformationThread(
            threadHandle,
            ThreadImpersonationToken,
            &tokenHandle,
            sizeof(HANDLE*)
            );
    }

    static
    bool
    ValidMembership(
        __in    HANDLE                        token,
        __in    PSID                          sid
        )
    {
        BOOL valid = FALSE;
        if (!CTokenSyscallProxy::RtlCheckTokenMembership(
            token, sid, &valid))
            return false;

        return valid == TRUE;
    }

    static
    bool
    ValidMembershipApp(
        __in    HANDLE                        token,
        __in    PSID                          sid
        )
    {
        BOOL valid = FALSE;
        if (!CTokenSyscallProxy::RtlCheckTokenMembershipEx(
            token, sid, CTMF_INCLUDE_APPCONTAINER, &valid))
            return false;

        return valid == TRUE;
    }
};