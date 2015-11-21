#pragma once

#include <Windows.h>

#include <iostream>
#include <string>
#include <map>

using namespace std;

class CProcAddressResolver
{
public:
    CProcAddressResolver();
    ~CProcAddressResolver();

    void* 
    ResolveProcAddress(
        __in const string& moduleName, 
        __in const string& procName
        );

    bool 
    GetModule(
        __in const string& moduleName
        );

    bool
    LoadModule(
        __in const string& moduleName
        );

private:
    map < const string, HMODULE >        m_moduleMaps;
};

