#pragma once

#include "SyscallProxy.h"

class CTokenManager
{
public:
	CTokenManager();
	~CTokenManager();

	std::uint64_t
	GetProcessToken(
		__in std::uint64_t			ProcessHandle,
		__in std::uint32_t			DesiredAccess
	);

	std::uint64_t
	GetThreadToken(
		__in std::uint64_t			ThreadHandle,
		__in std::uint32_t			DesiredAccess
	);

private:
	CSyscallProxy					m_SyscallProxy;
};

