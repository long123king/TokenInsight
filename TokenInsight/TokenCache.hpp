#pragma once
#include <memory>

using namespace std;

#include "TokenSyscallProxy.h"
#include "TokenUtility.hpp"

// CTokenCache provides a cache copy of the Token's specified information,
// Modifiable information can be modified in this copy in place and write back to the Token,
// A read-only pointer can be exposed to pretty format class.

template <class TOKEN_INFO_TYPE, TOKEN_INFORMATION_CLASS TokenInformationClass>
class CTokenCache
{
public:
    CTokenCache(
        __in const HANDLE token
        )
        :m_tokenInfoData(nullptr)
        ,m_token(token)
        ,m_success(LoadToCache())
    {

    }

    bool
    LoadToCache()
    {
        CTokenSyscallProxy::NtQueryInformationToken(
            m_token,
            TokenInformationClass,
            nullptr,
            0,
            reinterpret_cast<PDWORD>(&m_length));

        if (m_length > 0)
            m_tokenInfoData.reset(reinterpret_cast<TOKEN_INFO_TYPE*>(new (nothrow) uint8_t[m_length]));

        if (m_tokenInfoData)
            memset(m_tokenInfoData.get(), 0, m_length);
        else
            return false;

        return CTokenSyscallProxy::NtQueryInformationToken(
            m_token,
            TokenInformationClass,
            m_tokenInfoData.get(),
            m_length,
            reinterpret_cast<PDWORD>(&m_length));
    }

    virtual
    bool
    WriteBackToken()
    {
        return CTokenSyscallProxy::NtSetInformationToken(
            m_token,
            TokenInformationClass,
            m_tokenInfoData.get(),
            m_length);
    }

    const TOKEN_INFO_TYPE*
    Instance() const
    {
        if (m_success)
            return m_tokenInfoData.get();

        return nullptr;
    }

    const size_t
    Length() const
    {
        return m_length;
    }

    bool
    Valid() const
    {
        return m_success;
    }

protected:
    unique_ptr<TOKEN_INFO_TYPE>     m_tokenInfoData;
    const HANDLE                    m_token;
    bool                            m_success;
    uint32_t                        m_length;
};

class CTokenUser 
    : public CTokenCache<TOKEN_USER, TokenUser>
{
public:
    CTokenUser(
        __in const HANDLE token
        )
        :CTokenCache<TOKEN_USER, TokenUser>(token)
    {}
};

class CTokenGroups 
    : public CTokenCache<TOKEN_GROUPS, TokenGroups>
{
public:
    CTokenGroups(
        __in const HANDLE token
        )
        :CTokenCache<TOKEN_GROUPS, TokenGroups>(token)
        ,m_resetToDefault(false)
    {}

    unique_ptr<SID>
    GetLogonSid()
    {
        if (!m_success || !m_tokenInfoData)
            return nullptr;

        for (size_t i = 0; i < m_tokenInfoData->GroupCount; i++)
        {
            if ((m_tokenInfoData->Groups[i].Attributes & SE_GROUP_LOGON_ID) != 0)
            {
                size_t sid_len = CTokenUtility::GetSidLength(m_tokenInfoData->Groups[i].Sid);
                void* buffer = new uint8_t[sid_len];
                if (!buffer)
                    return nullptr;

                memcpy(buffer, m_tokenInfoData->Groups[i].Sid, sid_len);
                unique_ptr<SID> logon_sid(static_cast<PISID>(buffer));
                return logon_sid;
            }
        }

        return nullptr;
    }

    bool
    Enable(
        __in PSID groupSid
        )
    {        
        if (!m_success || !m_tokenInfoData)
            return false;

        if (!CTokenUtility::IsValidSid(groupSid))
            return false;

        for (size_t i = 0; i < m_tokenInfoData->GroupCount; i++)
        {
            if (CTokenUtility::IsSidsEqual(groupSid, m_tokenInfoData->Groups[i].Sid))
            {
                m_tokenInfoData->Groups[i].Attributes |= SE_GROUP_ENABLED;
                return true;
            }
        }

        return false;
    }

    bool
    Disable(
        __in PSID groupSid
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        if (!CTokenUtility::IsValidSid(groupSid))
            return false;

        for (size_t i = 0; i < m_tokenInfoData->GroupCount; i++)
        {
            if (CTokenUtility::IsSidsEqual(groupSid, m_tokenInfoData->Groups[i].Sid))
            {
                m_tokenInfoData->Groups[i].Attributes &= ~SE_GROUP_ENABLED;
                return true;
            }
        }

        return false;
    }

    bool 
    ResetToDefault()
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        m_resetToDefault = true;
        return true;
    }

    virtual
    bool
    WriteBackToken() override
    {
        return CTokenSyscallProxy::NtAdjustGroupsToken(
            m_token,
            m_resetToDefault,
            m_tokenInfoData.get(),
            m_length,
            NULL,
            NULL
            );
    }

private:
    bool    m_resetToDefault;
};

class CTokenPrivileges 
    : public CTokenCache<TOKEN_PRIVILEGES, TokenPrivileges>
{
public:
    CTokenPrivileges(
        __in const HANDLE token
        )
        :CTokenCache<TOKEN_PRIVILEGES, TokenPrivileges>(token)
        ,m_disableAll(false)
    {}

    bool
    Enable(
        __in LUID privilege
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        for (size_t i = 0; i < m_tokenInfoData->PrivilegeCount; i++)
        {
            if (m_tokenInfoData->Privileges[i].Luid.HighPart == privilege.HighPart && 
                m_tokenInfoData->Privileges[i].Luid.LowPart == privilege.LowPart)
            {
                m_tokenInfoData->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;
                return true;
            }
        }
        return false;
    }

    bool
    Disable(
        __in LUID privilege
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        for (size_t i = 0; i < m_tokenInfoData->PrivilegeCount; i++)
        {
            if (m_tokenInfoData->Privileges[i].Luid.HighPart == privilege.HighPart && 
                m_tokenInfoData->Privileges[i].Luid.LowPart == privilege.LowPart)
            {
                m_tokenInfoData->Privileges[i].Attributes |= SE_PRIVILEGE_REMOVED;
                return true;
            }
        }

        return false;
    }

    bool
    DisableAll()
    {
        if (!m_success || !m_tokenInfoData)
            return false;
        
        m_disableAll = true;
        return true;
    }

    virtual
    bool
    WriteBackToken() override
    {
        return CTokenSyscallProxy::NtAdjustPrivilegesToken(
            m_token,
            m_disableAll,
            m_tokenInfoData.get(),
            m_length,
            NULL,
            NULL
            );
    }

private:
    bool        m_disableAll;
};

class CTokenDefaultDACL 
    : public CTokenCache<TOKEN_DEFAULT_DACL, TokenDefaultDacl>
{
public:
    CTokenDefaultDACL(
        __in const HANDLE token
        )
        :CTokenCache<TOKEN_DEFAULT_DACL, TokenDefaultDacl>(token)
    {}    

    // TODO: add some interface to modify this DACL.
};

class CTokenOwner 
    : public CTokenCache < TOKEN_OWNER, TokenOwner >
{
public:
    CTokenOwner(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_OWNER, TokenOwner>(token)
    {}

    bool
    Reset(
        __in PSID sid
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        size_t length = sizeof(TOKEN_OWNER) + CTokenUtility::GetSidLength(sid);
        void* buffer = new (nothrow) uint8_t[length];
        if (!buffer)
            return false;
        else
            memset(buffer, 0, length);

        unique_ptr<TOKEN_OWNER> new_token_info(static_cast<TOKEN_OWNER*>(buffer));
        new_token_info->Owner = static_cast<uint8_t*>(buffer) + sizeof(TOKEN_OWNER);
        if (!CopySid(length - sizeof(TOKEN_OWNER), new_token_info->Owner, sid))
            return false;

        m_tokenInfoData.swap(new_token_info);
        m_length = length;

        return true;
    }
};

class CTokenPrimaryGroup 
    : public CTokenCache < TOKEN_PRIMARY_GROUP, TokenPrimaryGroup >
{
public:
    CTokenPrimaryGroup(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_PRIMARY_GROUP, TokenPrimaryGroup >(token)
    {}

    bool
    Reset(
        __in PSID sid
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        size_t length = sizeof(TOKEN_PRIMARY_GROUP) + CTokenUtility::GetSidLength(sid);
        void* buffer = new (nothrow) uint8_t[length];
        if (!buffer)
            return false;
        else
            memset(buffer, 0, length);

        unique_ptr<TOKEN_PRIMARY_GROUP> new_token_info(static_cast<TOKEN_PRIMARY_GROUP*>(buffer));
        new_token_info->PrimaryGroup = static_cast<uint8_t*>(buffer) + sizeof(TOKEN_PRIMARY_GROUP);
        if (!CopySid(length - sizeof(TOKEN_PRIMARY_GROUP), new_token_info->PrimaryGroup, sid))
            return false;

        m_tokenInfoData.swap(new_token_info);
        m_length = length;

        return true;
    }
};

class CTokenSessionId 
    : public CTokenCache < DWORD, TokenSessionId >
{
public:
    CTokenSessionId(
        __in const HANDLE token
        ) 
        :CTokenCache < DWORD, TokenSessionId >(token)
    {}

    bool
    Reset(
        __in uint32_t newSessionId
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        *m_tokenInfoData.get() = newSessionId;
        return true;
    }
};

class CTokenStatistics 
    : public CTokenCache < TOKEN_STATISTICS, TokenStatistics >
{
public:
    CTokenStatistics(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_STATISTICS, TokenStatistics >(token)
    {}
};

class CTokenRestrictedSids 
    : public CTokenCache < TOKEN_GROUPS, TokenRestrictedSids >
{
public:
    CTokenRestrictedSids(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_GROUPS, TokenRestrictedSids >(token)
    {}
};

class CTokenSource 
    : public CTokenCache < TOKEN_SOURCE, TokenSource >
{
public:
    CTokenSource(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_SOURCE, TokenSource >(token)
    {}
};

class CTokenType 
    : public CTokenCache < TOKEN_TYPE, TokenType >
{
public:
    CTokenType(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_TYPE, TokenType >(token)
    {}
};

class CTokenGroupsAndPrivileges 
    : public CTokenCache < TOKEN_GROUPS_AND_PRIVILEGES, TokenGroupsAndPrivileges >
{
public:
    CTokenGroupsAndPrivileges(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_GROUPS_AND_PRIVILEGES, TokenGroupsAndPrivileges >(token)
    {}
};

class CTokenSandBoxInert 
    : public CTokenCache < DWORD, TokenSandBoxInert >
{
public:
    CTokenSandBoxInert(
        __in const HANDLE token
        ) 
        :CTokenCache < DWORD, TokenSandBoxInert >(token)
    {}
};

class CTokenOrigin 
    : public CTokenCache < TOKEN_ORIGIN, TokenOrigin >
{
public:
    CTokenOrigin(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_ORIGIN, TokenOrigin >(token)
    {}

    bool
    Reset(
        __in LUID origin
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        m_tokenInfoData->OriginatingLogonSession = origin;
        return true;
    }
};

class CTokenElevationType 
    : public CTokenCache < TOKEN_ELEVATION_TYPE, TokenElevationType >
{
public:
    CTokenElevationType(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_ELEVATION_TYPE, TokenElevationType >(token)
    {}
};

class CTokenLinkedToken 
    : public CTokenCache < TOKEN_LINKED_TOKEN, TokenLinkedToken >
{
public:
    CTokenLinkedToken(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_LINKED_TOKEN, TokenLinkedToken >(token)
    {}

    // TODO: add some interface to modify this Linked Token.
};

class CTokenElevation 
    : public CTokenCache < TOKEN_ELEVATION, TokenElevation >
{
public:
    CTokenElevation(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_ELEVATION, TokenElevation >(token)
    {}
};

class CTokenHasRestrictions 
    : public CTokenCache < DWORD, TokenHasRestrictions >
{
public:
    CTokenHasRestrictions(
        __in const HANDLE token
        ) 
        :CTokenCache < DWORD, TokenHasRestrictions >(token)
    {}
};

class CTokenVirtualizationAllowed 
    : public CTokenCache < DWORD, TokenVirtualizationAllowed >
{
public:
    CTokenVirtualizationAllowed(
        __in const HANDLE token
        ) 
        :CTokenCache < DWORD, TokenVirtualizationAllowed >(token)
    {}

    bool
    Reset(
        __in uint32_t newVirtualizationAllowed
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        *m_tokenInfoData.get() = newVirtualizationAllowed;
        return true;
    }
};

class CTokenVirtualizationEnabled 
    : public CTokenCache < DWORD, TokenVirtualizationEnabled >
{
public:
    CTokenVirtualizationEnabled(
        __in const HANDLE token
        ) 
        :CTokenCache < DWORD, TokenVirtualizationEnabled >(token)
    {}

    bool
    Reset(
        __in uint32_t newVirtualizationEnabled
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        *m_tokenInfoData.get() = newVirtualizationEnabled;
        return true;
    }
};

class CTokenAccessInformation 
    : public CTokenCache < TOKEN_ACCESS_INFORMATION, TokenAccessInformation >
{
public:
    CTokenAccessInformation(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_ACCESS_INFORMATION, TokenAccessInformation >(token)
    {}
};

class CTokenIntegrityLevel 
    : public CTokenCache < TOKEN_MANDATORY_LABEL, TokenIntegrityLevel >
{
public:
    CTokenIntegrityLevel(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_MANDATORY_LABEL, TokenIntegrityLevel >(token)
    {}

    bool
    Reset(
        __in PISID newTokenIntegrityLevel
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        size_t length = sizeof(TOKEN_MANDATORY_LABEL) + CTokenUtility::GetSidLength(newTokenIntegrityLevel);
        void* buffer = new (nothrow) uint8_t[length];
        if (!buffer)
            return false;
        else
            memset(buffer, 0, length);

        unique_ptr<TOKEN_MANDATORY_LABEL> new_token_info(static_cast<TOKEN_MANDATORY_LABEL*>(buffer));
        new_token_info->Label.Sid = static_cast<uint8_t*>(buffer) + sizeof(TOKEN_MANDATORY_LABEL);
        new_token_info->Label.Attributes = m_tokenInfoData->Label.Attributes;
        if (!CopySid(length - sizeof(TOKEN_MANDATORY_LABEL), new_token_info->Label.Sid, newTokenIntegrityLevel))
            return false;

        m_tokenInfoData.swap(new_token_info);
        m_length = length;

        return true;
    }
};

class CTokenMandatoryPolicy 
    : public CTokenCache < TOKEN_MANDATORY_POLICY, TokenMandatoryPolicy >
{
public:
    CTokenMandatoryPolicy(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_MANDATORY_POLICY, TokenMandatoryPolicy >(token)
    {}

    bool
    Reset(
        __in uint32_t newTokenMandatoryPolicy
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        m_tokenInfoData->Policy = newTokenMandatoryPolicy;
        return true;
    }
};

class CTokenUIAccess 
    : public CTokenCache < DWORD, TokenUIAccess >
{
public:
    CTokenUIAccess(
        __in const HANDLE token
        ) 
        :CTokenCache < DWORD, TokenUIAccess >(token)
    {}

    bool
    Reset(
        __in uint32_t newUIAccess
        )
    {
        if (!m_success || !m_tokenInfoData)
            return false;

        *m_tokenInfoData.get() = newUIAccess;
        return true;
    }
};

class CTokenLogonSid 
    : public CTokenCache < TOKEN_GROUPS, TokenLogonSid >
{
public:
    CTokenLogonSid(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_GROUPS, TokenLogonSid >(token)
    {}
};

class CTokenIsAppContainer 
    : public CTokenCache < DWORD, TokenIsAppContainer >
{
public:
    CTokenIsAppContainer(
        __in const HANDLE token
        ) 
        :CTokenCache < DWORD, TokenIsAppContainer >(token)
    {}
};

class CTokenCapabilities 
    : public CTokenCache < TOKEN_GROUPS, TokenCapabilities >
{
public:
    CTokenCapabilities(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_GROUPS, TokenCapabilities >(token)
    {}
};

class CTokenAppContainerSid 
    : public CTokenCache <  TOKEN_APPCONTAINER_INFORMATION, TokenAppContainerSid >
{
public:
    CTokenAppContainerSid(
        __in const HANDLE token
        ) 
        :CTokenCache <  TOKEN_APPCONTAINER_INFORMATION, TokenAppContainerSid >(token)
    {}
};

class CTokenAppContainerNumber 
    : public CTokenCache < DWORD, TokenAppContainerNumber >
{
public:
    CTokenAppContainerNumber(
        __in const HANDLE token
        ) 
        :CTokenCache < DWORD, TokenAppContainerNumber >(token)
    {}
};

class CTokenUserClaimAttributes 
    : public CTokenCache < CLAIM_SECURITY_ATTRIBUTES_INFORMATION, TokenUserClaimAttributes >
{
public:
    CTokenUserClaimAttributes(
        __in const HANDLE token
        ) 
        :CTokenCache < CLAIM_SECURITY_ATTRIBUTES_INFORMATION, TokenUserClaimAttributes >(token)
    {}
};

class CTokenDeviceClaimAttributes 
    : public CTokenCache < CLAIM_SECURITY_ATTRIBUTES_INFORMATION, TokenDeviceClaimAttributes >
{
public:
    CTokenDeviceClaimAttributes(
        __in const HANDLE token
        ) 
        :CTokenCache < CLAIM_SECURITY_ATTRIBUTES_INFORMATION, TokenDeviceClaimAttributes >(token)
    {}
};

class CTokenDeviceGroups 
    : public CTokenCache < TOKEN_GROUPS, TokenDeviceGroups >
{
public:
    CTokenDeviceGroups(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_GROUPS, TokenDeviceGroups >(token)
    {}    
};

class CTokenRestrictedDeviceGroups 
    : public CTokenCache < TOKEN_GROUPS, TokenRestrictedDeviceGroups >
{
public:
    CTokenRestrictedDeviceGroups(
        __in const HANDLE token
        ) 
        :CTokenCache < TOKEN_GROUPS, TokenRestrictedDeviceGroups >(token)
    {}    
};

