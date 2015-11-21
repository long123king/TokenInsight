#include "ProcAddressResolver.h"

CProcAddressResolver::CProcAddressResolver()
{}

CProcAddressResolver::~CProcAddressResolver()
{
    for (auto& it : m_moduleMaps)
        FreeLibrary(it.second);

    m_moduleMaps.clear();
}

void* 
CProcAddressResolver::ResolveProcAddress(
    __in const string& moduleName,
    __in const string& procName
    )
{
    if (m_moduleMaps.find(moduleName) == m_moduleMaps.end())
        GetModule(moduleName);

    try
    {
        return GetProcAddress(m_moduleMaps.at(moduleName), procName.c_str());
    }
    catch (out_of_range&)
    {
        cerr << "Fail to get module handle. " << endl;
    }
    catch (exception&)
    {
        cerr << "Fail to resolve procedure address: [ "
            << moduleName
            << " : "
            << procName
            << " ]"
            << endl;
    }

    return nullptr;
}

bool
CProcAddressResolver::GetModule(
    __in const string& moduleName
    )
{
    HMODULE handle_module = GetModuleHandleA(moduleName.c_str());
    if (INVALID_HANDLE_VALUE != handle_module)
        m_moduleMaps[moduleName] = handle_module;
    else
        return LoadModule(moduleName);

    return true;
}

bool
CProcAddressResolver::LoadModule(
    __in const string& moduleName
    )
{
    HMODULE handle_module = LoadLibraryA(moduleName.c_str());
    if (INVALID_HANDLE_VALUE != handle_module)
        m_moduleMaps[moduleName] = handle_module;
    else
        return false;

    return true;
}