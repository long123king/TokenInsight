#pragma once

#include <map>
#include <cstdint>
#include <sstream>
#include <vector>
#include <iomanip>
#include <memory>

using namespace std;

#include <Windows.h>
#include <Sddl.h>

#include "SafeObject.h"
#include "TokenSyscallProxy.h"

struct cmp_str
{
    bool operator()(char const *a, char const *b) const
    {
        return std::strcmp(a, b) < 0;
    }
};

class CBitFieldAnalyzer
{
public:
    CBitFieldAnalyzer()
    {}

    CBitFieldAnalyzer(
        __in const map<uint32_t, const char*>& definitions
        )
    {
        for (auto it = definitions.begin();
            it != definitions.end();
            it++)
        {
            m_definitions[it->first] = it->second;
        }
    }

    CBitFieldAnalyzer(
        __in map<uint32_t, const char*>&& definitions
        )
        :m_definitions(move(definitions))
    {
    }

    string
    GetText(
        __in const uint32_t compound,
        __in bool pureText = false
        )
    {
        stringstream ss;
        if (!pureText)
            ss << "0x" <<  hex << noshowbase << setw(8) << setfill('0') << compound << "(";

        for (auto it = m_definitions.begin();
            it != m_definitions.end();
            it++)
        {            
            if (it->first & compound)
                ss << it->second << ",";
        }

        if (!pureText)
            ss << ")";

        return ss.str();
    }

private:
    map<uint32_t, const char*> m_definitions;
};

class CEnvironmentProxy
{
public:
    static
    auto_h::SafeHandle
    GetCurrentProcess()
    {
        return OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
    }

    static
    uint64_t
    GetFakeCurrentProcess()
    {
        return static_cast<uint64_t>(-1);
    }

    static
    uint64_t
    GetFakeCurrentThread()
    {
        return static_cast<uint64_t>(-2);
    }

    static
    auto_h::SafeHandle
    GetCurrentThread()
    {
        return OpenThread(PROCESS_ALL_ACCESS, false, GetCurrentThreadId());
    }
};

class CAccessToken 
{
public:
    CAccessToken(
        __in HANDLE tokenHandle
        )
        :m_tokenHandle(tokenHandle)
    {}

    CAccessToken(
        __in auto_h::SafeHandle&& tokenHandle
        )
        :m_tokenHandle(tokenHandle)
    {}

    bool
    Valid()
    {
        return INVALID_HANDLE_VALUE != m_tokenHandle.Get();
    }

    auto_h::SafeHandle m_tokenHandle;
};

class CTokenUtility
{
public:
    static
    string
    GetWellKnownAccount(
        __in const string& sidText
        )
    {
        auto it = s_wellknown_sids.find(sidText.c_str());

        if (it != s_wellknown_sids.end())
            return it->second;

        if (sidText.find("S-1-5-5-") == 0 && sidText.rfind("-") > 7)
            return "Logon Session";

        if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-500") == sidText.length() - 4)
            return "Administrator";

        if (sidText.find("S-1-5-21") == 0 && sidText.rfind("-501") == sidText.length() - 4)
            return "Guest";

        return "";
    }

    static
    string
    GetIntegrityLevelText(
        __in const string& sidText
        )
    {
        auto it = s_integrity_level_texts.find(sidText.c_str());

        if (it != s_integrity_level_texts.end())
            return it->second;

        return "";
    }

    static
    string
    GetIntegrityLevelSid(
        __in IntegrityLevel level
        )
    {
        auto it = s_integrity_level_sids.find(level);

        if (it != s_integrity_level_sids.end())
            return it->second;

        return "";
    }

    static
    string
    GetImpersonationLevel(
        __in SECURITY_IMPERSONATION_LEVEL level
        )
    {
        auto it = s_impersonation_levels.find(level);

        if (it != s_impersonation_levels.end())
            return it->second;

        return "";
    }

    static
    string
    GetElevationTypeText(
        __in TOKEN_ELEVATION_TYPE  type
        )
    {
        auto it = s_elevation_types.find(type);

        if (it != s_elevation_types.end())
            return it->second;

        return "";
    }

    static
    string
    GetMandatoryPolity(
        __in uint32_t policy
        )
    {
        static CBitFieldAnalyzer s_MandatoryPolicyAnalyzer {{
            { 0x00000001, "no_write_up" },
            { 0x00000002, "no_read_up"},
            { 0x00000002, "no_execute_up"}
            }};

        return s_MandatoryPolicyAnalyzer.GetText(policy);
    }

    static
    wstring
    GetSidTextW(
        __in PSID sid
        )
    {
        wchar_t buffer[1024] = { 0, };
        UNICODE_STRING unicode_str = { 0, 1024, static_cast<PWSTR>(buffer) };
        if (!CTokenSyscallProxy::RtlConvertSidToUnicodeString(&unicode_str, sid, false))
            return L"";

        wstring wstr(unicode_str.Buffer, unicode_str.Length / sizeof(wchar_t));
        return wstr;
    }

    static
    string
    GetSidTextA(
        __in PSID sid
        )
    {
        wstring wstr_sid = GetSidTextW(sid);
        string str_sid(wstr_sid.begin(), wstr_sid.end());
        return str_sid;
    }

    static
    string
    GetTokenTypeText(
        __in TOKEN_TYPE type
        )
    {
        if (TokenPrimary == type)
            return "Primary";
        else if (TokenImpersonation == type)
            return "Impersonation";

        return "";
    }

    static
    string
    GetGroupsAttrText(
        __in uint32_t attr,
        __in bool     pureText = false
        )
    {
        static CBitFieldAnalyzer s_GroupsAttrAnalyzer {{
            { 0x00000004, "enabled" },
            { 0x00000002, "default" },
            { 0x00000020, "integrity" },
            { 0x00000040, "integrity-enabled" },
            { 0xC0000000, "logon-id" },
            { 0x00000001, "mandatory" },
            { 0x00000008, "owner" },
            { 0x00000010, "deny-only" },
            { 0x20000000, "resource" }
            }};

        return s_GroupsAttrAnalyzer.GetText(attr, pureText);
    }

    static
    string
    GetACEFlagText(
        __in uint32_t flag,
        __in bool     pureText = false
        )
    {
        static CBitFieldAnalyzer s_ACEFlagAnalyzer {{
            { 0x1,  "OBJECT_INHERIT_ACE" },
            { 0x2,  "CONTAINER_INHERIT_ACE" },
            { 0x4,  "NO_PROPAGATE_INHERIT_ACE" },
            { 0x8,  "INHERIT_ONLY_ACE" },
            { 0x10, "INHERITED_ACE" }
            }};

        return s_ACEFlagAnalyzer.GetText(flag, pureText);
    }

    static
    string
    GetPrivilegeAttrText(
        __in uint32_t attr,
        __in bool     pureText = false
        )
    {
        static CBitFieldAnalyzer s_ACEFlagAnalyzer {{
            { 0x1,        "enabled_default" },
            { 0x2,        "enabled" },
            { 0x4,        "removed" },
            { 0x80000000, "used_for_access" }
            }};

        return s_ACEFlagAnalyzer.GetText(attr, pureText);
    }

    static
    string
    GetPrivilegeText(
        __in const LUID* luid
        )
    {
        char privilege_name[1024] = { 0, };

        DWORD privilege_len = 1024;
        if (BOOLIFY(LookupPrivilegeNameA(NULL, const_cast<PLUID>(luid), privilege_name, &privilege_len)))
            return string(privilege_name, privilege_len);

        return "";
    }

    static
    LUID
    GetPrivilegeValue(
        __in const string& privilegeLiteral
        )
    {
        LUID privilege_value = {0, };
        LookupPrivilegeValueA(NULL, privilegeLiteral.c_str(),&privilege_value);
        return privilege_value;
    }

    static
    string
    GetAccountText(
        __in PSID sid
        )
    {
        string str_sid = GetSidTextA(sid);

        string str_account = GetWellKnownAccount(str_sid);
        if (!str_account.empty())
            return str_account;

        char account_name[1024] = { 0, };
        char domain_name[1024] = { 0, };

        uint32_t account_len = 1024;
        uint32_t domain_len = 1024;

        SID_NAME_USE use;

        if (BOOLIFY(LookupAccountSidA(NULL, sid, account_name,
            reinterpret_cast<LPDWORD>(&account_len), domain_name, reinterpret_cast<LPDWORD>(&domain_len), &use)))
        {
            string account(account_name, account_len);
            string domain(domain_name, domain_len);

            if (!domain.empty())
                domain += "/";

            domain += account;

            return domain;
        }
        else
            return str_sid;

        return "";
    }

    static
    string
    GetAccessMaskText(
        uint32_t mask
        )
    {
        stringstream ss;
        ss << hex << showbase << mask << "(";
        if (mask & 0x10000000)
            ss << "rwx";
        else
        {
            if (mask & 0x80000000)
                ss << "r";
            else
                ss << "-";

            if (mask & 0x40000000)
                ss << "w";
            else
                ss << "-";

            if (mask & 0x20000000)
                ss << "x";
            else
                ss << "-";
        }

        ss << ")";
        return ss.str();
    }

    //public RtlLengthSid
    //RtlLengthSid proc near
    //movzx   eax, byte ptr[rcx + 1]
    //lea     eax, ds:8[rax * 4]
    //retn
    //RtlLengthSid endp

    static
    uint32_t
    GetSidLength(
        __in const PSID sid
        )
    {
        //return GetLengthSid(Sid);
        if (nullptr == sid)
            return 0;

        uint32_t len = *(reinterpret_cast<const uint8_t*>(sid) + 1);
        return len * 4 + 8;
    }    

    static
    bool
    IsValidSid(
        __in const PSID sid
        )
    {
        if (!sid)
            return false;

        PISID sid_a = static_cast<PISID>(sid);
        if (1 == sid_a->Revision && sid_a->SubAuthorityCount <= 0x0F)
            return true;

        return false;
    }

    static
    bool
    IsSidsEqual(
        __in const PSID sidA,
        __in const PSID sidB
        )
    {
        PISID sid_a = static_cast<PISID>(sidA);
        PISID sid_b = static_cast<PISID>(sidB);

        if (sid_a == sid_b)
            return true;

        if (!IsValidSid(sidA) || !IsValidSid(sidB))
            return false;

        if (sid_a->SubAuthorityCount != sid_b->SubAuthorityCount)
            return false;

        return 0 == memcmp(sidA, sidB, sid_a->SubAuthorityCount * 4 + 8);
    }

    static
    auto_h::SafeLocal
    GetSidByLiteral(
        __in const string& sidText
        )
    {
        PSID sid = nullptr;
        if (BOOLIFY(ConvertStringSidToSidA(sidText.c_str(), &sid)))
            return reinterpret_cast<HLOCAL>(sid);

        return nullptr;
    }

    static
    LUID
    GetLuidByText(
        __in const string& luidText
        )
    {
        LUID luid = { 0, 0 };
        if (BOOLIFY(LookupPrivilegeValueA(NULL, luidText.c_str(), &luid)))
            return luid;

        return luid;
    }

    static
    bool
    DeleteAceFromACL(
        __in uint32_t   index,
        __in PACL        ACL
        )
    {
        return BOOLIFY(DeleteAce(ACL, index));
    }

    static
    bool
    AddAceToACL(
        __in PACL     ACL,
        __in uint32_t revision,
        __in uint32_t startingIndex,
        __in uint8_t* aces,
        __in uint32_t length
        )
    {
        return BOOLIFY(AddAce(ACL, revision, startingIndex, aces, length));
    }

    static
    NTSTATUS
    RtlSidHashInitialize
    (
        __in PSID_AND_ATTRIBUTES               groups,
        __in size_t                            groupsCount,
        __inout PSID_AND_ATTRIBUTES_HASH       hashBuffer
        )
    {
        if (NULL == hashBuffer)
            return 0xC000000D;

        memset(hashBuffer, 0, 0x110);

        if (0 == groupsCount || NULL == groups)
            return 0;

        hashBuffer->SidCount = groupsCount;
        hashBuffer->SidAttr = groups;

        if (groupsCount > 0x40)
            groupsCount = 0x40;

        if (0 == groupsCount) // Redundent ?
            return 0;

        size_t bit_pos = 1;

        for (size_t i = 0; i < groupsCount; i++)
        {
            PISID sid = reinterpret_cast<PISID>((groups + i)->Sid); 

            size_t sub_authority_count = sid->SubAuthorityCount;

            DWORD sub_authority = sid->SubAuthority[sub_authority_count - 1];

            *(size_t*)(&hashBuffer->Hash[(sub_authority & 0x0000000F)]) |= bit_pos;
            *(size_t*)(&hashBuffer->Hash[((sub_authority & 0x000000F0) >> 4) + 0x10]) |= bit_pos;

            bit_pos <<= 1;
        }

        return 0;
    }

private:
    static const map<const char*, const char*, cmp_str>                             s_wellknown_sids;
    static const map<const char*, const char*, cmp_str>                             s_integrity_level_texts;
    static const map<const IntegrityLevel, const char*>                    s_integrity_level_sids;
    static const map<const SECURITY_IMPERSONATION_LEVEL, const char*>      s_impersonation_levels;
    static const map<const TOKEN_ELEVATION_TYPE, const char*>              s_elevation_types;

public:
    static const SID s_seUntrustedMandatorySid;
    static const SID s_seLowMandatorySid;
    static const SID s_seMediumMandatorySid;
    static const SID s_seHighMandatorySid;
    static const SID s_seSystemMandatorySid;

    static const SID s_everyoneSid;
    static const SID s_localSid;
    static const SID s_worldSid;
    static const SID s_consoleLogonSid;
    static const SID s_localSystemSid;
    static const SID s_localServiceSid;
    static const SID s_networkServiceSid;
    static const SID s_creatorOwnerSid;
    static const SID s_creatorGroupSid;
    static const SID2 s_administratorsSid;
    static const SID2 s_usersSid;
    static const SID2 s_guestsSid;
    static const SID2 s_internetCapabilitySid;

    static const vector<const char*> s_all_privileges;
};

const map<const char*, const char*, cmp_str> CTokenUtility::s_wellknown_sids {{
    { "S-1-1-0",          "Everyone" },
    { "S-1-2-0",          "Local" },
    { "S-1-2-1",          "Console Logon" },
    { "S-1-5-18",         "Local System" },
    { "S-1-5-32-544",     "BUILTIN/Administrators" },
    { "S-1-5-32-545",     "BUILTIN/Users" },
    { "S-1-5-32-546",     "BUILTIN/Guests" },
    { "S-1-5-32-555",     "BUILTIN/\\Remote Desktop Users" },
    { "S-1-5-32-578",     "BUILTIN/\\Hyper-V Administrators" }
    }};

const map<const char*, const char*, cmp_str> CTokenUtility::s_integrity_level_texts {{
    { "S-1-16-0",         "Untrusted(0)" },
    { "S-1-16-4096",      "Low(1)" },
    { "S-1-16-8192",      "Medium(2)" },
    { "S-1-16-12288",     "High(3)" },
    { "S-1-16-16384",     "System(4)" }
    }};

const map<const IntegrityLevel, const char*> CTokenUtility::s_integrity_level_sids {{
    { IntegrityLevel_Untrusted,        "S-1-16-0"},
    { IntegrityLevel_Low,              "S-1-16-4096"},
    { IntegrityLevel_Medium,           "S-1-16-8192"},
    { IntegrityLevel_High,             "S-1-16-12288"},
    { IntegrityLevel_System,           "S-1-16-16384"}
    }};

const map<const SECURITY_IMPERSONATION_LEVEL, const char*> CTokenUtility::s_impersonation_levels {{
    { SecurityAnonymous,              "Anonymous"},
    { SecurityIdentification,         "Indentification"},
    { SecurityImpersonation,          "Impersonation"},
    { SecurityDelegation,             "Delegation"}
    }};

const map<const TOKEN_ELEVATION_TYPE, const char*> CTokenUtility::s_elevation_types {{
    { TokenElevationTypeDefault,      "Default" },
    { TokenElevationTypeFull,         "Full" },
    { TokenElevationTypeLimited,      "Limited" }
    }};

const SID CTokenUtility::s_seUntrustedMandatorySid     {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x10}},{0x00000000}};
const SID CTokenUtility::s_seLowMandatorySid           {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x10}},{0x00001000}};
const SID CTokenUtility::s_seMediumMandatorySid        {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x10}},{0x00002000}};
const SID CTokenUtility::s_seHighMandatorySid          {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x10}},{0x00003000}};
const SID CTokenUtility::s_seSystemMandatorySid        {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x10}},{0x00004000}};

const SID CTokenUtility::s_everyoneSid                 {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x01}},{0x00000000}};
const SID CTokenUtility::s_localSid                    {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x02}},{0x00000000}};
const SID CTokenUtility::s_consoleLogonSid             {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x02}},{0x00000001}};
const SID CTokenUtility::s_localSystemSid              {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x05}},{0x00000012}};
const SID CTokenUtility::s_localServiceSid             {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x05}},{0x00000013}};
const SID CTokenUtility::s_networkServiceSid           {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x05}},{0x00000014}};
const SID CTokenUtility::s_creatorOwnerSid             {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x03}},{0x00000000}};
const SID CTokenUtility::s_creatorGroupSid             {0x01,0x01,{{0x00,0x00,0x00,0x00,0x00,0x03}},{0x00000001}};
const SID2 CTokenUtility::s_administratorsSid          {0x01,0x02,{{0x00,0x00,0x00,0x00,0x00,0x05}},{0x00000020, 0x00000220}};
const SID2 CTokenUtility::s_usersSid                   {0x01,0x02,{{0x00,0x00,0x00,0x00,0x00,0x05}},{0x00000020, 0x00000221}};
const SID2 CTokenUtility::s_guestsSid                  {0x01,0x02,{{0x00,0x00,0x00,0x00,0x00,0x05}},{0x00000020, 0x00000222}};
const SID2 CTokenUtility::s_internetCapabilitySid      {0x01,0x02,{{0x00,0x00,0x00,0x00,0x00,0x0f}},{0x00000003, 0x00000001}};

const vector<const char*> CTokenUtility::s_all_privileges { {
    "SeCreateTokenPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLockMemoryPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeMachineAccountPrivilege",
    "SeTcbPrivilege",
    "SeSecurityPrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege"
    "SeSystemProfilePrivilege"
    "SeSystemtimePrivilege"
    "SeProfileSingleProcessPrivilege"
    "SeIncreaseBasePriorityPrivilege"
    "SeCreatePagefilePrivilege"
    "SeCreatePermanentPrivilege"
    "SeBackupPrivilege"
    "SeRestorePrivilege"
    "SeShutdownPrivilege"
    "SeDebugPrivilege"
    "SeAuditPrivilege"
    "SeSystemEnvironmentPrivilege"
    "SeChangeNotifyPrivilege"
    "SeRemoteShutdownPrivilege"
    "SeUndockPrivilege"
    "SeSyncAgentPrivilege"
    "SeEnableDelegationPrivilege"
    "SeManageVolumePrivilege"
    "SeImpersonatePrivilege"
    "SeCreateGlobalPrivilege"
    "SeTrustedCredManAccessPrivilege"
    "SeRelabelPrivilege"
    "SeIncreaseWorkingSetPrivilege"
    "SeTimeZonePrivilege"
    "SeCreateSymbolicLinkPrivilege"
    } };