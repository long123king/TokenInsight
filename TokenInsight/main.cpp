// framework.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <sstream>
#include <algorithm>
#include <iomanip>
#include <fstream>

#include "TokenSyscallProxy.h"
#include "TokenUtility.hpp"

#include "TokenCache.hpp"
#include "TokenRepr.hpp"
#include "TokenStore.hpp" 
#include "SpawnWithToken.hpp"

void SpawnProcessWithToken(size_t tokenSourcePid, wstring newProcessName, PfnTransFunc transFunc)
{
    auto curr_token = CTokenStore::GetCurrentProcessToken();
    auto target_token = CTokenStore::GetProcessTokenByPid(tokenSourcePid);
    CTokenPrivileges token_privileges(curr_token->m_tokenHandle.Get());

    for (auto& privilege : CTokenUtility::s_all_privileges)
    {
        LUID luid = { 0, };
        if (LookupPrivilegeValueA(nullptr, privilege, &luid))
            token_privileges.Enable(luid);
    }
    bool bRet = token_privileges.WriteBackToken();

    PROCESS_INFORMATION proc_info = {0};
    STARTUPINFO startup_info = {0};
    startup_info.cb = sizeof(startup_info);

    if (!CSpawnWithToken::SpawnWithToken<PfnTransFunc>(
        target_token->m_tokenHandle.Get(),
        transFunc,
        newProcessName.c_str(), nullptr, nullptr, nullptr, false, 0, nullptr, nullptr, &startup_info, &proc_info
        ))
        cerr << "Fail to spawn new proces, last error is " << GetLastError() << endl;
    else
    {
        WaitForSingleObject(proc_info.hProcess, INFINITE);
        CloseHandle(proc_info.hProcess);
        CloseHandle(proc_info.hThread);
    }
}

int _tmain(int argc, _TCHAR* argv[])
{
    cout << "Usage: " << argv[1] << " [pid, default current pid]" << endl; 

    CTemplateTesterSuite template_test;
    if (argc <= 1)
        template_test.ReadToken(CTokenStore::GetCurrentProcessToken()->m_tokenHandle.Get());
    else
        template_test.ReadToken(CTokenStore::GetProcessTokenByPid(stoi(argv[1], nullptr, 0))->m_tokenHandle.Get());

    return 0;
}

