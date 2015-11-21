#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <map>

using namespace std;

#include <Windows.h>
#include "TokenCache.hpp"

class CFormatHex
{
public:
    explicit
    CFormatHex(
        __in const size_t    width,
        __in const bool        showbase,
        __in const bool        uppercase,
        __in const uint64_t value
        )
        :m_width(width)
        ,m_showbase(showbase)
        ,m_uppercase(uppercase)
        ,m_value(value)
    {}

    template <typename charT, typename traits>
    friend
    basic_ostream<charT, traits>&
    operator << (
        __in basic_ostream<charT, traits>&    strm,
        __in const CFormatHex&                formatHex
        )
    {
        strm << (formatHex.m_showbase ? "0x" : "")
             << noshowbase
             << (formatHex.m_uppercase ? uppercase : nouppercase)
             << hex
             << setw(formatHex.m_width)
             << setfill('0')
             << formatHex.m_value;

        return strm;
    }

private:
    size_t          m_width;
    bool            m_showbase;
    bool            m_uppercase;
    uint64_t        m_value;
};

class CPrettyPrinter
{
public:
    static
    string
    PrintBinary(
        __in const uint8_t*      data,
        __in const size_t        len,
        __in const size_t        base = 0
        )
    {
        stringstream ss;
        string readable_line;
        for (size_t i = 0; i < len; i++)
        {
            if (0 == i % 16)
            {
                ss << "|" << readable_line << "|"
                   << endl
                   << CFormatHex(16, true, false, base + i)
                   << ": ";

                readable_line.clear();
            }

            ss << CFormatHex(2, false, true, (unsigned int)(*(unsigned char*)(data + i)))
               << " ";

            readable_line += Escape(*(data + i));
        }

        if (0 != len % 16)
            ss << string((16 - len % 16) * 3, ' ');

        ss << "|" << readable_line << "|" << endl;

        return ss.str();
    }

    static
    string
    PrintBinary(
        __in const string&    str,
        __in const size_t     base = 0
        )
    {
        return PrintBinary(reinterpret_cast<const uint8_t*>(str.data()), str.length(), base);
    }

    static
    char
    Escape(
        __in char ch
        )
    {
        if (ch >= 0x7F)
            return '.';

        if (ch < 0x20)
            return '.';

        return ch;
    }

    static
    string
    AsInteger(
        __in const uint8_t*        value,
        __in size_t                length
        )
    {
        stringstream ss;
        
        ss << "0x";

        while (length > 0)
        {
            ss << hex << setw(2) << setfill('0') << static_cast<uint32_t>(*(value + (--length)));
        }

        return ss.str();
    }

    static
    string
    AsSequence(
        __in const uint8_t*        value,
        __in size_t                length,
        __in bool                  hasMore = false
        )
    {
        stringstream ss;
        
        size_t i = 0;
        while (i < length)
        {
            ss << hex << setw(2) << setfill('0') << static_cast<uint32_t>(*(value + (i++))) << " ";
        }

        if (hasMore)
            ss << "...";

        return ss.str();
    }

    static
    string
    PrintRepr(
        __in const string&        name,
        __in const uint8_t*       value,
        __in const size_t         length
        )
    {
        stringstream ss;
        ss << setw(s_column_1_width) << left << name
           << " : " 
           << setw(s_column_2_width) << left;

        if (length < 0x08)
            ss << AsInteger(value, length);
        else if (length < 0x20)
            ss << AsSequence(value, length);
        else 
            ss << AsSequence(value, 0x20, true);

        ss << endl;

        return ss.str();
    }

    static
    string
    PrintStr(
        __in const string&         name,
        __in const uint8_t*        value,
        __in const size_t          length,
        __in const string&         comments = ""
        )
    {
        stringstream ss;
        ss << setw(s_column_1_width) << left << name
           << " : " 
           << setw(s_column_2_width) << left;

        if (length < 0x08)
            ss << AsInteger(value, length);
        else if (length < 0x20)
            ss << AsSequence(value, length);
        else 
            ss << AsSequence(value, 0x20, true);

        ss << " : "
           << left << comments
           << endl;

        return ss.str();
    }

    static
    string
    PrintStr(
        __in const string&      name,
        __in const string&      value,
        __in const string&      comments = ""
        )
    {
        stringstream ss;

        ss << setw(s_column_1_width) << left << name
           << " : " 
           << setw(s_column_2_width) << left << value
           << " : "
           << left << comments
           << endl;

        return ss.str();
    }

private:
    static const uint32_t s_column_1_width    = 30;
    static const uint32_t s_column_2_width    = 120;
};

class CStructSlot
{
protected:
    string                                 m_name;
    string                                 m_type;

    string                                 m_doc;

    const uint8_t*                         m_rawData;
    size_t                                 m_length;
    size_t                                 m_nestedLevel;

    string                                 m_repr;
    string                                 m_str;

    vector<unique_ptr<CStructSlot>>        m_members;

public:

    CStructSlot(
        __in const string&      name,
        __in const string&      type,
        __in const string&      doc,
        __in const uint8_t*     rawData,
        __in const size_t       length,
        __in const size_t       nestedLevel
        )
        :m_name(name)
        ,m_type(type)
        ,m_doc(doc)
        ,m_rawData(rawData)
        ,m_length(length)
        ,m_nestedLevel(nestedLevel)
    {}

    virtual 
    string
    __name__()
    {
        return m_name;
    }

    virtual 
    string
    __type__()
    {
        return m_type;
    }

    virtual 
    string
    __doc__()
    {
        return m_doc;
    }

    virtual 
    string
    __str__()
    {
        if (m_str.empty())
            m_str = CPrettyPrinter::PrintStr(IndentedName(), Data(), Length(), Comment());

        for (auto& Member : m_members)
            m_str += Member->__str__();

        return m_str;
    }

    virtual 
    string
    __repr__()
    {
        if (m_repr.empty())
            m_repr = CPrettyPrinter::PrintRepr(IndentedName(), Data(), Length());

        for (auto& Member : m_members)
            m_repr += Member->__repr__();

        return m_repr;
    }

    virtual 
    const
    uint8_t*
    Data()
    {
        return m_rawData;
    }

    virtual 
    size_t
    Length()
    {
        return m_length;
    }

    virtual 
    string
    Comment()
    {
        return "";//QuotedType();
    }

protected:
    string
    QuotedType()
    {
        string quoted_type = "--<Type: ";
        quoted_type += m_type;
        quoted_type += ">--";

        return quoted_type;
    }

    string
    IndentedName()
    {
        if (0 == m_nestedLevel)
            return m_name;

        string indented_name((m_nestedLevel - 1) * 4, ' ');
        indented_name += " [+]";
        indented_name += m_name;

        return indented_name;
    }
};

template <class TypeT>
class CFieldInterpreter 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TypeT*     data, 
        __in size_t           len, 
        __in const string&    name = "",
        __in const size_t     nestedLevel = 0,
        __in const string&    type = "",
        __in const string&    doc = "",
        __in const string&    comment = ""
        )
        :m_data(data)
        ,m_comment(comment)
        ,CStructSlot(name, type, doc, reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        if (m_type.empty())
            m_type = typeid(TypeT).name();
    }

    virtual 
    string
    Comment()
    {
        if (!m_comment.empty())
            return m_comment;
        else
            return CStructSlot::Comment();
    }

private:
    const TypeT*        m_data;
    string              m_comment;
};

using AttrType = uint32_t;

template <>
class CFieldInterpreter < AttrType > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const AttrType    data,
        __in size_t            len,
        __in const string&     name = "[Data]",
        __in const size_t      nestedLevel = 0,
        __in const string&     comment = ""
        )
        :m_data(data)
        ,m_comment(comment)
        ,CStructSlot(name, "uint32_t", "uint32_t type that represents attributes", reinterpret_cast<const uint8_t*>(&m_data), len, nestedLevel)
    {}

    virtual 
    string
    Comment()
    {
        return m_comment;
    }

private:
    const AttrType    m_data;
    string            m_comment;
};


template <>
class CFieldInterpreter < PSID > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const PSID      data,
        __in size_t          len,
        __in const string&   name = "[Data]",
        __in const size_t    nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "PSID", "security identifiers", reinterpret_cast<const uint8_t*>(data), CTokenUtility::GetSidLength(data), nestedLevel)
    {}

    virtual 
    const
    uint8_t*
    Data()
    {
        static PSID s_empty_sid = 0;

        if (!m_data)
            return reinterpret_cast<const uint8_t*>(&s_empty_sid);

        return reinterpret_cast<const uint8_t*>(m_data);
    }

    virtual 
    size_t
    Length()
    {
        if (!m_data)
            return sizeof(PSID);

        return CTokenUtility::GetSidLength(m_data);
    }

    virtual 
    string
    Comment()
    {
        if (!m_data)
            return "";

        return CTokenUtility::GetAccountText(m_data);
    }

    virtual 
    string
    __str__()
    {
        if (!m_str.empty())
            return m_str;

        if (nullptr == m_data )
            m_str = CStructSlot::__str__();
        else
            m_str = CPrettyPrinter::PrintStr(IndentedName(), CTokenUtility::GetSidTextA(m_data), CTokenUtility::GetAccountText(m_data));

        return m_str;
    }

private:
    const PSID        m_data;    
};

template <>
class CFieldInterpreter < SID_AND_ATTRIBUTES > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const SID_AND_ATTRIBUTES*    data,
        __in size_t                       len,
        __in const string&                name = "[Data]",
        __in const size_t                 nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "SID_AND_ATTRIBUTES", "SIDs and their attributes", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->Sid)>>(m_data->Sid, sizeof(m_data->Sid), "Sid", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<AttrType>>(m_data->Attributes, sizeof(m_data->Attributes), "Attributes", m_nestedLevel+1, CTokenUtility::GetGroupsAttrText(m_data->Attributes, true)));
    }

private:
    const SID_AND_ATTRIBUTES*    m_data;    
};

template <>
class CFieldInterpreter < TOKEN_USER > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_USER*       data,
        __in size_t                  len,
        __in const string&           name = "",
        __in const size_t            nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_USER", "identifies the user associated with an access token.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->User)>>(&m_data->User, m_length, "User", m_nestedLevel+1));
    }

private:
    const TOKEN_USER*        m_data;
};

template <>
class CFieldInterpreter < SID_AND_ATTRIBUTES_HASH > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const SID_AND_ATTRIBUTES_HASH*    data,
        __in size_t                            len,
        __in const string&                     name = "",
        __in const size_t                      nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "SID_AND_ATTRIBUTES_HASH", "specifies a hash values for the specified array of security identifiers (SIDs).", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->SidCount)>>(&m_data->SidCount, sizeof(m_data->SidCount), "SidCount", m_nestedLevel+1));
        uint8_t* next_sid = reinterpret_cast<std::uint8_t*>(m_data->SidAttr);
        string item_name;
        for (size_t i = 0; i < m_data->SidCount; i++)
        {
            item_name = "SidAttr[";
            item_name += to_string(i);
            item_name += "]";

            m_members.push_back(make_unique<CFieldInterpreter<SID_AND_ATTRIBUTES>>(
                reinterpret_cast<PSID_AND_ATTRIBUTES>(next_sid), sizeof(SID_AND_ATTRIBUTES), item_name, m_nestedLevel+1));

            next_sid += sizeof(SID_AND_ATTRIBUTES);
        }

        for (size_t i = 0; i < SID_HASH_SIZE; i++)
        {
            item_name = "Hash[";
            item_name += to_string(i);
            item_name += "]";

            m_members.push_back(make_unique<CFieldInterpreter<SID_HASH_ENTRY>>(
                &(m_data->Hash[i]), sizeof(SID_HASH_ENTRY), item_name, m_nestedLevel+1));
        }

    }

private:
    const SID_AND_ATTRIBUTES_HASH*                m_data;
};

template <>
class CFieldInterpreter < LUID > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const LUID*        data,
        __in size_t             len,
        __in const string&      name = "",
        __in const size_t       nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "LUID", "a 64-bit value guaranteed to be unique only on the system on which it was generated.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->HighPart)>>(&m_data->HighPart, sizeof(m_data->HighPart), "HighPart", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->LowPart)>>(&m_data->LowPart, sizeof(m_data->LowPart), "LowPart", m_nestedLevel+1));
    }

    virtual
    string
    Comment()
    {
        return CTokenUtility::GetPrivilegeText(m_data);
    }

private:
    const LUID*                m_data;
};


template <>
class CFieldInterpreter < LUID_AND_ATTRIBUTES > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const LUID_AND_ATTRIBUTES*     data,
        __in size_t                         len,
        __in const string&                  name = "",
        __in const size_t                   nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "LUID_AND_ATTRIBUTES", "represents a locally unique identifier (LUID) and its attributes.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->Luid)>>(&m_data->Luid, sizeof(m_data->Luid), "Luid", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<AttrType>>(m_data->Attributes, sizeof(m_data->Attributes), "Attributes", m_nestedLevel+1, CTokenUtility::GetPrivilegeAttrText(m_data->Attributes, true)));
    }

private:
    const LUID_AND_ATTRIBUTES*    m_data;
};


template <>
class CFieldInterpreter < TOKEN_PRIVILEGES > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_PRIVILEGES*         data,
        __in size_t                          len,
        __in const string&                   name = "",
        __in const size_t                    nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_PRIVILEGES", "a set of privileges for an access token.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->PrivilegeCount)>>(&m_data->PrivilegeCount, sizeof(m_data->PrivilegeCount), "PrivilegeCount", m_nestedLevel+1));
        string item_name;
        for (size_t i = 0; i < m_data->PrivilegeCount; i++)
        {
            item_name = "Privileges[";
            item_name += to_string(i);
            item_name += "]";

            m_members.push_back(make_unique<CFieldInterpreter<LUID_AND_ATTRIBUTES>>(
                &m_data->Privileges[i], sizeof(LUID_AND_ATTRIBUTES), item_name, m_nestedLevel+1));
        }
    }

private:
    const TOKEN_PRIVILEGES*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_MANDATORY_POLICY > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_MANDATORY_POLICY*    data,
        __in size_t                           len,
        __in const string&                    name = "", 
        __in const size_t                     nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_PRIVILEGES", "a set of privileges for an access token.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<AttrType>>(m_data->Policy, sizeof(m_data->Policy), "Policy", m_nestedLevel+1, CTokenUtility::GetMandatoryPolity(m_data->Policy)));
    }

private:
    const TOKEN_MANDATORY_POLICY*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_ACCESS_INFORMATION > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_ACCESS_INFORMATION*     data,
        __in size_t                              len,
        __in const string&                       name = "",
        __in const size_t                        nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_ACCESS_INFORMATION", "specifies all the information in a token that is necessary to perform an access check.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<SID_AND_ATTRIBUTES_HASH>>((m_data->SidHash), sizeof(*(m_data->SidHash)), "SidHash", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<SID_AND_ATTRIBUTES_HASH>>((m_data->RestrictedSidHash), sizeof(*(m_data->RestrictedSidHash)), "RestrictedSidHash", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<TOKEN_PRIVILEGES>>((m_data->Privileges), sizeof(*(m_data->Privileges)), "Privileges", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->AuthenticationId)>>(&m_data->AuthenticationId, sizeof(m_data->AuthenticationId), "AuthenticationId", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<AttrType>>(m_data->TokenType, sizeof(m_data->TokenType), "TokenType", m_nestedLevel+1, CTokenUtility::GetTokenTypeText(m_data->TokenType)));
        m_members.push_back(make_unique<CFieldInterpreter<AttrType>>(m_data->ImpersonationLevel, sizeof(m_data->ImpersonationLevel), "ImpersonationLevel", m_nestedLevel+1, CTokenUtility::GetImpersonationLevel(m_data->ImpersonationLevel)));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->MandatoryPolicy)>>(&m_data->MandatoryPolicy, sizeof(m_data->MandatoryPolicy), "MandatoryPolicy", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->Flags)>>(&m_data->Flags, sizeof(m_data->Flags), "Flags", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->AppContainerNumber)>>(&m_data->AppContainerNumber, sizeof(m_data->AppContainerNumber), "AppContainerNumber", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<PSID>>(m_data->PackageSid, CTokenUtility::GetSidLength(m_data->PackageSid), "PackageSid", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<SID_AND_ATTRIBUTES_HASH>>((m_data->CapabilitiesHash), sizeof(*(m_data->CapabilitiesHash)), "CapabilitiesHash", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<PSID>>(m_data->TrustLevelSid, CTokenUtility::GetSidLength(m_data->TrustLevelSid), "TrustLevelSid", m_nestedLevel+1));

        bool integrity = VerifyGroupsHash();
    }

    bool
    VerifyGroupsHash()
    {
        SID_AND_ATTRIBUTES_HASH hash_1 = {0,};
        CTokenUtility::RtlSidHashInitialize(m_data->SidHash->SidAttr, m_data->SidHash->SidCount, &hash_1);

        SID_AND_ATTRIBUTES_HASH hash_2 = {0,};
        CTokenSyscallProxy::RtlSidHashInitialize(m_data->SidHash->SidAttr, m_data->SidHash->SidCount, &hash_2);

        return 0 == memcmp(hash_1.Hash, hash_2.Hash, 0x100) && 
            0 == memcmp(hash_1.Hash, m_data->SidHash->Hash, 0x100);
    }

private:
    const TOKEN_ACCESS_INFORMATION*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_OWNER > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_OWNER*      data,
        __in size_t                  len,
        __in const string&           name = "",
        __in const size_t            nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_OWNER", "contains the default owner security identifier (SID) that will be applied to newly created objects.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->Owner)>>(m_data->Owner, sizeof(m_data->Owner), "Owner", m_nestedLevel+1));
    }

private:
    const TOKEN_OWNER*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_GROUPS > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_GROUPS*    data,
        __in size_t                 len,
        __in const string&          name = "",
        __in const size_t           nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_GROUPS", "contains information about the group security identifiers (SIDs) in an access token.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->GroupCount)>>(&m_data->GroupCount, sizeof(m_data->GroupCount), "GroupCount", m_nestedLevel+1));
        string item_name;
        for (size_t i = 0; i < m_data->GroupCount; i++)
        {
            item_name = "Groups[";
            item_name += to_string(i);
            item_name += "]";

            m_members.push_back(make_unique<CFieldInterpreter<SID_AND_ATTRIBUTES>>(
                &(m_data->Groups[i]), sizeof(SID_AND_ATTRIBUTES), item_name, m_nestedLevel+1));
        }
    }

private:
    const TOKEN_GROUPS*    m_data;
};

template <>
class CFieldInterpreter < ACE_HEADER > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const ACE_HEADER*      data,
        __in size_t                 len,
        __in const string&          name = "",
        __in const size_t           nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "ACE_HEADER", "defines the type and size of an access control entry (ACE).", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->AceType)>>(&m_data->AceType, sizeof(m_data->AceType), "AceType", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->AceFlags)>>(&m_data->AceFlags, sizeof(m_data->AceFlags), "AceFlags", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->AceSize)>>(&m_data->AceSize, sizeof(m_data->AceSize), "AclSize", m_nestedLevel+1));
    }

private:
    const ACE_HEADER*    m_data;
};

template <>
class CFieldInterpreter < ACCESS_ALLOWED_ACE > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const ACCESS_ALLOWED_ACE*     data,
        __in size_t                        len,
        __in const string&                 name = "",
        __in const size_t                  nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "COMMON_ACE", "defines an access control entry (ACE) for the discretionary access control list (DACL) that controls access to an object.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        PSID sid = const_cast<PSID>(static_cast<const void*>(&m_data->SidStart));
        m_members.push_back(make_unique<CFieldInterpreter<ACE_HEADER>>(&m_data->Header, sizeof(m_data->Header), "Header", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<AttrType>>(m_data->Mask, sizeof(m_data->Mask), "Mask", m_nestedLevel+1, CTokenUtility::GetAccessMaskText(m_data->Mask)));
        m_members.push_back(make_unique<CFieldInterpreter<PSID>>(sid, CTokenUtility::GetSidLength(sid), "SidStart", m_nestedLevel+1));
    }

private:
    const ACCESS_ALLOWED_ACE*    m_data;
};

template <>
class CFieldInterpreter < ACL > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const ACL*             data,
        __in size_t                 len,
        __in const string&          name = "",
        __in const size_t           nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "ACL", "the header of an access control list (ACL). A complete ACL consists of an ACL structure followed by an ordered list of zero or more access control entries (ACEs).", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->AclRevision)>>(&m_data->AclRevision, sizeof(m_data->AclRevision), "AclRevision", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->Sbz1)>>(&m_data->Sbz1, sizeof(m_data->Sbz1), "Sbz1", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->AclSize)>>(&m_data->AclSize, sizeof(m_data->AclSize), "AclSize", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->AceCount)>>(&m_data->AceCount, sizeof(m_data->AceCount), "AceCount", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->Sbz2)>>(&m_data->Sbz2, sizeof(m_data->Sbz2), "Sbz2", m_nestedLevel+1));
        string item_name;
        const ACE_HEADER* header = reinterpret_cast<const ACE_HEADER*>(reinterpret_cast<const uint8_t*>(m_data) + sizeof(ACL));
        for (size_t i = 0; i < m_data->AceCount; i++)
        {
            item_name = "Ace[";
            item_name += to_string(i);
            item_name += "]";            

            m_members.push_back(make_unique<CFieldInterpreter<ACCESS_ALLOWED_ACE>>(
                reinterpret_cast<const ACCESS_ALLOWED_ACE*>(header), header->AceSize, item_name, m_nestedLevel+1));

            header = reinterpret_cast<const ACE_HEADER*>(reinterpret_cast<const uint8_t*>(header) + header->AceSize);
        }
    }

private:
    const ACL*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_DEFAULT_DACL > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_DEFAULT_DACL*           data,
        __in size_t                              len,
        __in const string&                       name = "",
        __in const size_t                        nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_DEFAULT_DACL", "specifies a discretionary access control list (DACL).", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<ACL>>(m_data->DefaultDacl, sizeof(m_data->DefaultDacl), "DefaultDacl", m_nestedLevel+1));
    }

private:
    const TOKEN_DEFAULT_DACL*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_PRIMARY_GROUP > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_PRIMARY_GROUP*     data,
        __in size_t                         len,
        __in const string&                  name = "",
        __in const size_t                   nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_PRIMARY_GROUP", "specifies a group security identifier (SID) for an access token.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<PSID>>(m_data->PrimaryGroup, sizeof(m_data->PrimaryGroup), "PrimaryGroup", m_nestedLevel+1));
    }

private:
    const TOKEN_PRIMARY_GROUP*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_SOURCE > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_SOURCE*             data,
        __in size_t                          len,
        __in const string&                   name = "",
        __in const size_t                    nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_SOURCE", "identifies the source of an access token.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->SourceName)>>(&m_data->SourceName, TOKEN_SOURCE_LENGTH, "SourceName", m_nestedLevel+1, "", "", std::string(m_data->SourceName, strlen(m_data->SourceName) < TOKEN_SOURCE_LENGTH ? strlen(m_data->SourceName) : TOKEN_SOURCE_LENGTH)));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->SourceIdentifier)>>(&m_data->SourceIdentifier, sizeof(m_data->SourceIdentifier), "SourceIdentifier", m_nestedLevel+1));
    }

private:
    const TOKEN_SOURCE*    m_data;
};


template <>
class CFieldInterpreter < LARGE_INTEGER > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const LARGE_INTEGER*            data,
        __in size_t                          len,
        __in const string&                   name = "",
        __in const size_t                    nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "LARGE_INTEGER", "Represents a 64-bit signed integer value.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->LowPart)>>(&m_data->LowPart, sizeof(m_data->LowPart), "LowPart", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->HighPart)>>(&m_data->HighPart, sizeof(m_data->HighPart), "HighPart", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->QuadPart)>>(&m_data->QuadPart, sizeof(m_data->QuadPart), "QuadPart", m_nestedLevel+1));
    }

private:
    const LARGE_INTEGER*        m_data;
};

template <>
class CFieldInterpreter < TOKEN_STATISTICS > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_STATISTICS*      data,
        __in size_t                       len,
        __in const string&                name = "",
        __in const size_t                 nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_STATISTICS", "contains information about an access token.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<LUID>>(&m_data->TokenId, sizeof(m_data->TokenId), "TokenId", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<LUID>>(&m_data->AuthenticationId, sizeof(m_data->AuthenticationId), "AuthenticationId", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<decltype(m_data->ExpirationTime)>>(&m_data->ExpirationTime, sizeof(m_data->ExpirationTime), "ExpirationTime", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<AttrType>>(m_data->TokenType, sizeof(m_data->TokenType), "TokenType", m_nestedLevel+1, CTokenUtility::GetTokenTypeText((m_data->TokenType))));
        m_members.push_back(make_unique<CFieldInterpreter<AttrType>>(m_data->ImpersonationLevel, sizeof(m_data->ImpersonationLevel), "ImpersonationLevel", m_nestedLevel+1, CTokenUtility::GetImpersonationLevel(m_data->ImpersonationLevel)));
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->DynamicCharged, sizeof(m_data->DynamicCharged), "DynamicCharged", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->DynamicAvailable, sizeof(m_data->DynamicAvailable), "DynamicAvailable", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->GroupCount, sizeof(m_data->GroupCount), "GroupCount", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->PrivilegeCount, sizeof(m_data->PrivilegeCount), "PrivilegeCount", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<LUID>>(&m_data->ModifiedId, sizeof(m_data->ModifiedId), "ModifiedId", m_nestedLevel+1));
    }

private:
    const TOKEN_STATISTICS*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_GROUPS_AND_PRIVILEGES > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_GROUPS_AND_PRIVILEGES*      data,
        __in size_t                                  len,
        __in const string&                           name = "",
        __in const size_t                            nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_GROUPS_AND_PRIVILEGES", "contains information about the group security identifiers (SIDs) and privileges in an access token.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->SidCount, sizeof(m_data->SidCount), "SidCount", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->SidLength, sizeof(m_data->SidLength), "SidLength", m_nestedLevel+1));
        string item_name;
        for (size_t i = 0; i < m_data->SidCount; i++)
        {
            item_name = "Sids[";
            item_name += to_string(i);
            item_name += "]";            

            m_members.push_back(make_unique<CFieldInterpreter<SID_AND_ATTRIBUTES>>(
                m_data->Sids + i, sizeof(m_data->Sids[i]), item_name, m_nestedLevel+1));
        }
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->RestrictedSidCount, sizeof(m_data->RestrictedSidCount), "RestrictedSidCount", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->RestrictedSidLength, sizeof(m_data->RestrictedSidLength), "RestrictedSidLength", m_nestedLevel+1));
        for (size_t i = 0; i < m_data->RestrictedSidCount; i++)
        {
            item_name = "RestrictedSidCount[";
            item_name += to_string(i);
            item_name += "]";            

            m_members.push_back(make_unique<CFieldInterpreter<SID_AND_ATTRIBUTES>>(
                m_data->RestrictedSids + i, sizeof(m_data->RestrictedSids[i]), item_name, m_nestedLevel+1));
        }
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->PrivilegeCount, sizeof(m_data->PrivilegeCount), "PrivilegeCount", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->PrivilegeLength, sizeof(m_data->PrivilegeLength), "PrivilegeLength", m_nestedLevel+1));
        for (size_t i = 0; i < m_data->PrivilegeCount; i++)
        {
            item_name = "Privileges[";
            item_name += to_string(i);
            item_name += "]";            

            m_members.push_back(make_unique<CFieldInterpreter<LUID_AND_ATTRIBUTES>>(
                m_data->Privileges + i, sizeof(m_data->Privileges[i]), item_name, m_nestedLevel+1));
        }
        m_members.push_back(make_unique<CFieldInterpreter<LUID>>(&m_data->AuthenticationId,    sizeof(m_data->AuthenticationId), "AuthenticationId", m_nestedLevel+1));
    }

private:
    const TOKEN_GROUPS_AND_PRIVILEGES*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_ORIGIN > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_ORIGIN*            data,
        __in size_t                         len,
        __in const string&                  name = "",
        __in const size_t                   nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_ORIGIN", "contains information about the origin of the logon session.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<LUID>>(&m_data->OriginatingLogonSession, sizeof(m_data->OriginatingLogonSession), "OriginatingLogonSession", m_nestedLevel+1));
    }

private:
    const TOKEN_ORIGIN*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_ELEVATION > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_ELEVATION*           data,
        __in size_t                           len,
        __in const string&                    name = "",
        __in const size_t                     nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_ELEVATION", "indicates whether a token has elevated privileges.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->TokenIsElevated, sizeof(m_data->TokenIsElevated), "TokenIsElevated", m_nestedLevel+1));
    }

private:
    const TOKEN_ELEVATION*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_MANDATORY_LABEL > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_MANDATORY_LABEL*      data,
        __in size_t                            len,
        __in const string&                     name = "",
        __in const size_t                      nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_MANDATORY_LABEL", "specifies the mandatory integrity level for a token.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<SID_AND_ATTRIBUTES>>(&m_data->Label, sizeof(m_data->Label), "Label", m_nestedLevel+1));
    }

private:
    const TOKEN_MANDATORY_LABEL*    m_data;
};

template <>
class CFieldInterpreter < TOKEN_APPCONTAINER_INFORMATION > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const TOKEN_APPCONTAINER_INFORMATION*      data,
        __in size_t                                     len,
        __in const string&                              name = "",
        __in const size_t                               nestedLevel = 0
        )
        :m_data(data)
        ,CStructSlot(name, "TOKEN_APPCONTAINER_INFORMATION", "specifies all the information in a token that is necessary for an app container.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<PSID>>(m_data->TokenAppContainer, CTokenUtility::GetSidLength(m_data->TokenAppContainer), "TokenAppContainer", m_nestedLevel+1));
    }

private:
    const TOKEN_APPCONTAINER_INFORMATION*    m_data;
};

// Partial implemented, the detailed attributes are not parsed, seems useless.
template <>
class CFieldInterpreter < CLAIM_SECURITY_ATTRIBUTES_INFORMATION > 
    : public CStructSlot
{
public:
    CFieldInterpreter(
        __in const CLAIM_SECURITY_ATTRIBUTES_INFORMATION*      data,
        __in size_t                                            len,
        __in const string&                                     name = "",
        __in const size_t                                      nestedLevel = 0
       )
       :m_data(data)
       ,CStructSlot(name, "CLAIM_SECURITY_ATTRIBUTES_INFORMATION", "defines the security attributes for the claim.", reinterpret_cast<const uint8_t*>(data), len, nestedLevel)
    {
        m_members.push_back(make_unique<CFieldInterpreter<WORD>>(&m_data->Version, sizeof(m_data->Version), "Version", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<WORD>>(&m_data->Reserved, sizeof(m_data->Reserved), "Reserved", m_nestedLevel+1));
        m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(&m_data->AttributeCount, sizeof(m_data->AttributeCount), "AttributeCount", m_nestedLevel+1));
    }

private:
    const CLAIM_SECURITY_ATTRIBUTES_INFORMATION*    m_data;
};

class CTokenStruct 
    : public CStructSlot
{
public:
    CTokenStruct(
        __in const HANDLE token,
        __in const string& name
        )
        :m_token(token)
        ,m_user(m_token)
        ,m_owner(m_token)
        ,m_groups(m_token)
        ,m_privileges(m_token)
        ,m_defaultDACL(m_token)
        ,m_primaryGroup(m_token)
        ,m_sessionId(m_token)
        ,m_restrictedSids(m_token)
        ,m_source(m_token)
        ,m_statistics(m_token)
        ,m_type(m_token)
        ,m_groupsAndPrivileges(m_token)
        ,m_sandboxInert(m_token)
        ,m_origin(m_token)
        ,m_elevationType(m_token)
        ,m_linkedToken(m_token)
        ,m_elevation(m_token)
        ,m_hasRestrictions(m_token)
        ,m_virtualizationAllowed(m_token)
        ,m_virtualizationEnabled(m_token)
        ,m_accessInfo(m_token)
        ,m_integrityLevel(m_token)
        ,m_mandatoryPolicy(m_token)
        ,m_uiAccess(m_token)
        ,m_logonSid(m_token)
        ,m_isAppContainer(m_token)
        ,m_capability(m_token)
        ,m_appContainerSid(m_token)
        ,m_appContainerNumber(m_token)
        ,m_userClaimAttr(m_token)
        ,m_deviceClaimAttr(m_token)
        ,m_deviceGroups(m_token)
        ,m_restrictedDeviceGroups(m_token)
        ,CStructSlot(name, "Token", "gather all token related information.", nullptr, 0, 0)
    {
        if (m_user.Valid()) 
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_USER>>(m_user.Instance(), m_user.Length(), "User", m_nestedLevel+1));
        
        if (m_owner.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_OWNER>>(m_owner.Instance(), m_owner.Length(), "Owner", m_nestedLevel+1));
        
        if (m_groups.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_GROUPS>>(m_groups.Instance(), m_groups.Length(), "Groups", m_nestedLevel+1));
        
        if (m_privileges.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_PRIVILEGES>>(m_privileges.Instance(), m_privileges.Length(), "Privileges", m_nestedLevel+1));
        
        if (m_defaultDACL.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_DEFAULT_DACL>>(m_defaultDACL.Instance(), m_defaultDACL.Length(), "DefaultDACL", m_nestedLevel+1));
        
        if (m_primaryGroup.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_PRIMARY_GROUP>>(m_primaryGroup.Instance(), m_primaryGroup.Length(), "PrimaryGroup", m_nestedLevel+1));
        
        if (m_sessionId.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(m_sessionId.Instance(), m_sessionId.Length(), "SessionId", m_nestedLevel+1));
        
        if (m_restrictedSids.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_GROUPS>>(m_restrictedSids.Instance(), m_restrictedSids.Length(), "RestrictedSids", m_nestedLevel+1));
        
        if (m_source.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_SOURCE>>(m_source.Instance(), m_source.Length(), "Source", m_nestedLevel+1));
        
        if (m_statistics.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_STATISTICS>>(m_statistics.Instance(), m_statistics.Length(), "Statistics", m_nestedLevel+1));
        
        if (m_type.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<AttrType>>(*m_type.Instance(), m_type.Length(), "Type", m_nestedLevel+1, CTokenUtility::GetTokenTypeText(*m_type.Instance())));
        
        if (m_groupsAndPrivileges.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_GROUPS_AND_PRIVILEGES>>(m_groupsAndPrivileges.Instance(), m_groupsAndPrivileges.Length(), "GroupsAndPrivileges", m_nestedLevel+1));
        
        if (m_sandboxInert.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(m_sandboxInert.Instance(), m_sandboxInert.Length(), "SandboxInert", m_nestedLevel+1));
        
        if (m_origin.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_ORIGIN>>(m_origin.Instance(), m_origin.Length(), "Origin", m_nestedLevel+1));
        
        if (m_elevationType.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<AttrType>>(*m_elevationType.Instance(), m_elevationType.Length(), "ElevationType", m_nestedLevel+1, CTokenUtility::GetElevationTypeText(*m_elevationType.Instance())));
        
        if (m_elevation.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_ELEVATION>>(m_elevation.Instance(), m_elevation.Length(), "Elevation", m_nestedLevel+1));
        
        if (m_hasRestrictions.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(m_hasRestrictions.Instance(), m_hasRestrictions.Length(), "HasRestrictions", m_nestedLevel+1));
        
        if (m_virtualizationAllowed.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(m_virtualizationAllowed.Instance(), m_virtualizationAllowed.Length(), "VirtualizationAllowed", m_nestedLevel+1));
        
        if (m_virtualizationEnabled.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(m_virtualizationEnabled.Instance(), m_virtualizationEnabled.Length(), "VirtualizationEnabled", m_nestedLevel+1));
        
        if (m_accessInfo.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_ACCESS_INFORMATION>>(m_accessInfo.Instance(), m_accessInfo.Length(), "AccessInfo", m_nestedLevel+1));
        
        if (m_integrityLevel.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_MANDATORY_LABEL>>(m_integrityLevel.Instance(), m_integrityLevel.Length(), "IntegrityLevel", m_nestedLevel+1));
        
        if (m_mandatoryPolicy.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_MANDATORY_POLICY>>(m_mandatoryPolicy.Instance(), m_mandatoryPolicy.Length(), "MandatoryPolicy", m_nestedLevel+1));
        
        if (m_uiAccess.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(m_uiAccess.Instance(), m_uiAccess.Length(), "UIAccess", m_nestedLevel+1));
        
        if (m_logonSid.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_GROUPS>>(m_logonSid.Instance(), m_logonSid.Length(), "LogonSid", m_nestedLevel+1));
        
        if (m_isAppContainer.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(m_isAppContainer.Instance(), m_isAppContainer.Length(), "IsAppContainer", m_nestedLevel+1));
        
        if (m_capability.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_GROUPS>>(m_capability.Instance(), m_capability.Length(), "Capabilities", m_nestedLevel+1));
        
        if (m_appContainerSid.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_APPCONTAINER_INFORMATION>>(m_appContainerSid.Instance(), m_appContainerSid.Length(), "AppContainerSid", m_nestedLevel+1));
        
        if (m_appContainerNumber.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<DWORD>>(m_appContainerNumber.Instance(), m_appContainerNumber.Length(), "AppContainerNumber", m_nestedLevel+1));
        
        if (m_userClaimAttr.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<CLAIM_SECURITY_ATTRIBUTES_INFORMATION>>(m_userClaimAttr.Instance(), m_userClaimAttr.Length(), "UserClaimAttributes", m_nestedLevel+1));
        
        if (m_deviceClaimAttr.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<CLAIM_SECURITY_ATTRIBUTES_INFORMATION>>(m_deviceClaimAttr.Instance(), m_deviceClaimAttr.Length(), "DeviceClaimAttributes", m_nestedLevel+1));
        
        if (m_deviceGroups.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_GROUPS>>(m_deviceGroups.Instance(), m_deviceGroups.Length(), "DeviceGroups", m_nestedLevel+1));
        
        if (m_restrictedDeviceGroups.Valid())
            m_members.push_back(make_unique<CFieldInterpreter<TOKEN_GROUPS>>(m_restrictedDeviceGroups.Instance(), m_restrictedDeviceGroups.Length(), "RestrictedDeviceGroups", m_nestedLevel+1));
    }

    const HANDLE
    GetLinkedToken()
    {
        if (!m_linkedToken.Valid())
            return NULL;

        return m_linkedToken.Instance()->LinkedToken;
    }

private:
    const HANDLE                       m_token;
    CTokenUser                         m_user;
    CTokenOwner                        m_owner;
    CTokenGroups                       m_groups;
    CTokenPrivileges                   m_privileges;
    CTokenDefaultDACL                  m_defaultDACL;
    CTokenPrimaryGroup                 m_primaryGroup;
    CTokenSessionId                    m_sessionId;
    CTokenRestrictedSids               m_restrictedSids;
    CTokenSource                       m_source;
    CTokenStatistics                   m_statistics;
    CTokenType                         m_type;
    CTokenGroupsAndPrivileges          m_groupsAndPrivileges;
    CTokenSandBoxInert                 m_sandboxInert;
    CTokenOrigin                       m_origin;
    CTokenElevationType                m_elevationType;
    CTokenLinkedToken                  m_linkedToken;
    CTokenElevation                    m_elevation;
    CTokenHasRestrictions              m_hasRestrictions;
    CTokenVirtualizationAllowed        m_virtualizationAllowed;
    CTokenVirtualizationEnabled        m_virtualizationEnabled;
    CTokenAccessInformation            m_accessInfo;
    CTokenIntegrityLevel               m_integrityLevel;
    CTokenMandatoryPolicy              m_mandatoryPolicy;
    CTokenUIAccess                     m_uiAccess;
    CTokenLogonSid                     m_logonSid;
    CTokenIsAppContainer               m_isAppContainer; // This is not retrieved from kernel
    CTokenCapabilities                 m_capability;
    CTokenAppContainerSid              m_appContainerSid;
    CTokenAppContainerNumber           m_appContainerNumber;
    CTokenUserClaimAttributes          m_userClaimAttr;
    CTokenDeviceClaimAttributes        m_deviceClaimAttr;
    CTokenDeviceGroups                 m_deviceGroups;
    CTokenRestrictedDeviceGroups       m_restrictedDeviceGroups;
};

class CTemplateTesterSuite
{
public:
    void 
    ReadToken(
        __in const HANDLE token
        )
    {
        if (!token)
            return;
        
        ofstream out("template_output.txt", ios::out | ios::trunc);

        CTokenStruct current_token(token, "CurrentToken");
        out << current_token.__str__();

        CTokenStruct linked_token(current_token.GetLinkedToken(), "LinkedToken");
        out << linked_token.__str__();
    }

    void 
    DumpToken(
        __in const HANDLE token,
        __in ostream& out
        )
    {
        if (!token)
            return;

        CTokenStruct current_token(token, "CurrentToken");
        out << current_token.__str__();

        CTokenStruct linked_token(current_token.GetLinkedToken(), "LinkedToken");
        out << linked_token.__str__();
    }
};
