#pragma once

#include "TokenCache.hpp"
#include "TokenRepr.hpp"
#include "TokenStore.hpp"

using PfnTransFunc =
unique_ptr<CAccessToken>(*)(
    __in HANDLE originalToken
    );

class CSpawnWithToken
{
public:
    template<typename TokenTrans, typename...ArgT>
    static
    bool
    SpawnWithToken(
        __in HANDLE originalToken,
        __in TokenTrans transFunc,
        __in ArgT...args
        )
    {
        auto new_token = transFunc(originalToken);
        if (!new_token)
            return false;

        auto result = CreateProcessAsUser(new_token->m_tokenHandle.Get(), args...);
        return result;
    }

    static
    unique_ptr<CAccessToken>
    IdenticalTrans(
        __in HANDLE originalToken
        )
    {
        HANDLE new_token = nullptr;

        if (!CTokenSyscallProxy::NtDuplicateToken(originalToken, TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, true, TokenPrimary, &new_token))
            return nullptr;

        return make_unique<CAccessToken>(new_token);
    }

    static
    unique_ptr<CAccessToken>
    LowILTrans(
        __in HANDLE originalToken
        )
    {
        auto new_token = CTokenStore::CreateImpersonationToken(originalToken, MAXIMUM_ALLOWED, FALSE, NULL, SecurityImpersonation, TokenPrimary);
        if (!new_token || !new_token->Valid())
            return nullptr;    

        CTokenIntegrityLevel integrity_level(new_token->m_tokenHandle.Get());
        integrity_level.Reset(const_cast<PISID>(&CTokenUtility::s_seLowMandatorySid));
        if (!integrity_level.WriteBackToken())
            return nullptr;

        return new_token;
    }

    static
    unique_ptr<CAccessToken>
    RestrictedTrans(
        __in HANDLE originalToken
        )
    {
        CTokenGroups org_groups_cache(originalToken);
        auto logon_sid = org_groups_cache.GetLogonSid();
        
        TOKEN_GROUPS disabled_groups = {1, {const_cast<PISID>(logon_sid.get()), 0}};
        auto load_driver_privilege = CTokenUtility::GetPrivilegeValue("SeLoadDriverPrivilege");
        TOKEN_PRIVILEGES removed_privileges = {1, {load_driver_privilege, 0}};
        auto new_token = CTokenStore::CreateRestrictedToken(originalToken, 0, NULL, &removed_privileges, &disabled_groups);
        if (!new_token || !new_token->Valid())
            return nullptr; 

        CTokenGroups groups_cache(new_token->m_tokenHandle.Get());
        CFieldInterpreter<TOKEN_GROUPS> groups_repr(groups_cache.Instance(), groups_cache.Length(), "Groups");
        string groups_str = groups_repr.__str__();

        CTokenPrivileges privilege_cache(new_token->m_tokenHandle.Get());
        CFieldInterpreter<TOKEN_PRIVILEGES> privileges_repr(privilege_cache.Instance(), privilege_cache.Length(), "Privileges");
        string privilege_str = privileges_repr.__str__();

        CTokenRestrictedSids restricted_cache(new_token->m_tokenHandle.Get());
        CFieldInterpreter<TOKEN_GROUPS> restricted_repr(restricted_cache.Instance(), restricted_cache.Length(), "RestrictedSids");
        string restricted_str = restricted_repr.__str__();

        return new_token;
    }

    static
    unique_ptr<CAccessToken>
    LowBoxTrans(
        __in HANDLE originalToken
        )
    {
        size_t len = 8 + 4*8;
        void* buffer = new uint8_t[len];
        memset(buffer, 0, len);

        unique_ptr<SID> app_container_sid(static_cast<PISID>(buffer));

        app_container_sid->Revision = 1;
        app_container_sid->SubAuthorityCount = 8;
        app_container_sid->IdentifierAuthority.Value[5] = 15;
        app_container_sid->SubAuthority[0] = 2;
        app_container_sid->SubAuthority[1] = 1220793744;
        app_container_sid->SubAuthority[2] = 3666789380;
        app_container_sid->SubAuthority[3] = 189579892;
        app_container_sid->SubAuthority[4] = 1973497788;
        app_container_sid->SubAuthority[5] = 2854962754;
        app_container_sid->SubAuthority[6] = 2836109804;
        app_container_sid->SubAuthority[7] = 3864561331;

        OBJECT_ATTRIBUTES obj_attr = {0,};
        obj_attr.Length = sizeof(obj_attr);

        HANDLE saved_handles[1] = {originalToken};
        DWORD saved_handles_count = 1;

        SID_AND_ATTRIBUTES capabilities = {const_cast<PISID2>(&CTokenUtility::s_internetCapabilitySid), 0x00000004};

        auto new_token = CTokenStore::CreateLowBoxToken(
            originalToken,
            TOKEN_ALL_ACCESS, 
            &obj_attr,
            app_container_sid.get(), 
            1, 
            &capabilities,
            saved_handles_count, 
            saved_handles);

        if (!new_token || !new_token->Valid())
            return nullptr; 

        CTokenStruct groups_cache(new_token->m_tokenHandle.Get(), "LowBoxToken");
        string groups_str = groups_cache.__str__();

        return new_token;
    }
};