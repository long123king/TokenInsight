#include "TokenManager.h"


CTokenManager::CTokenManager()
{
}

CTokenManager::~CTokenManager()
{
}

std::uint64_t
CTokenManager::GetProcessToken(
	__in std::uint64_t			ProcessHandle,
	__in std::uint32_t			DesiredAccess
)
{
	std::uint64_t result_handle = 0;
	if (!m_SyscallProxy.NtOpenProcessToken(ProcessHandle, DesiredAccess, &result_handle))
		throw std::exception("Fail to get process token");
		
	std::cout << "Hooked Version: " << std::hex << result_handle << std::endl;

	//if (OpenProcessToken(reinterpret_cast<HANDLE>(ProcessHandle), DesiredAccess, reinterpret_cast<PHANDLE>(&result_handle)))
	//	std::cout << "Original Version: " << std::hex << result_handle << std::endl;
	//else
	//	std::cout << "Original Last Error: " << std::hex << GetLastError() << std::endl;

	return result_handle;
}

std::uint64_t
CTokenManager::GetThreadToken(
	__in std::uint64_t			ThreadHandle,
	__in std::uint32_t			DesiredAccess
)
{
	std::uint64_t result_handle = 0;
	if (!m_SyscallProxy.NtOpenThreadToken(ThreadHandle, DesiredAccess, false, &result_handle))
		throw std::exception("Fail to get thread token");
		
	std::cout << "Hooked Version: " << std::hex << result_handle << std::endl;

	//if (OpenThreadToken(reinterpret_cast<HANDLE>(ThreadHandle), DesiredAccess, false, reinterpret_cast<PHANDLE>(&result_handle)))
	//	std::cout << "Original Version: " << std::hex << result_handle << std::endl;
	//else
	//	std::cout << "Original Last Error: " << std::hex << GetLastError() << std::endl;

	return result_handle;
}