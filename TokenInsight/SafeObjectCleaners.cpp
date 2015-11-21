#include "SafeObject.h"

namespace auto_h
{
    namespace clean_fn
    {
        bool ClnCloseHandle(HANDLE handle) { return BOOLIFY(CloseHandle(handle)); };
        bool ClnFreeLibrary(HMODULE handle) { return BOOLIFY(FreeLibrary(handle)); };
        bool ClnLocalFree(HLOCAL handle) { return (LocalFree(handle) == nullptr); };
        bool ClnGlobalFree(HGLOBAL handle) { return (GlobalFree(handle) == nullptr); };
        bool ClnUnmapViewOfFile(void* handle) { return BOOLIFY(UnmapViewOfFile(handle)); };
        bool ClnCloseDesktop(HDESK handle) { return BOOLIFY(CloseDesktop(handle)); };
        bool ClnCloseWindowStation(HWINSTA handle) { return BOOLIFY(CloseWindowStation(handle)); };
        bool ClnCloseServiceHandle(SC_HANDLE handle) { return BOOLIFY(CloseServiceHandle(handle)); };
        bool ClnVirtualFree(void* handle) { return BOOLIFY(VirtualFree(handle, 0, MEM_RELEASE)); };
    };
};
