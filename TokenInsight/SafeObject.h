#pragma once

#include <Windows.h>

#define BOOLIFY(x) (FALSE != (x))

namespace auto_h
{
    namespace clean_fn
    {
        bool ClnCloseHandle(HANDLE handle);
        bool ClnFreeLibrary(HMODULE handle);
        bool ClnLocalFree(HLOCAL handle);
        bool ClnGlobalFree(HGLOBAL handle);
        bool ClnUnmapViewOfFile(void* handle);
        bool ClnCloseDesktop(HDESK handle);
        bool ClnCloseWindowStation(HWINSTA handle);
        bool ClnCloseServiceHandle(SC_HANDLE handle);
        bool ClnVirtualFree(void* handle);
    }

    template <typename type_t, bool (*Cleanup)(type_t), void* InvalidValue>
    class SafeObject final
    {
        type_t m_obj;
    public:
        SafeObject() :
            m_obj(InvalidValue)
        {
        }

        SafeObject(
            __in const SafeObject &copy
            )
        {
            *this = copy;
        }

        SafeObject(
            __in const type_t& obj
            ) : m_obj(obj)
        {
        }
        
        SafeObject(
            __in const SafeObject&& obj
            )
        {
            *this = move(obj);
        }

        ~SafeObject()
        {
            Reset(nullptr);
        }

        const 
        bool 
        IsValid() const
        {
            return (m_obj != static_cast<type_t>(InvalidValue));
        }

        //copy
        SafeObject&
        operator=(
            __in const SafeObject& copy
            )
        {
            bool status = BOOLIFY(
                DuplicateHandle(
                    GetCurrentProcess(), 
                    copy.m_obj,
                    GetCurrentProcess(), 
                    &m_obj,
                    0, 
                    TRUE, 
                    DUPLICATE_SAME_ACCESS));

            if (!status)
                m_obj = InvalidValue;

            return *this;
        }
        
        const
        type_t
        operator()() const
        {
            return static_cast<type_t>(m_obj);
        }

        //move
        SafeObject&
        operator=(
            __inout SafeObject&& obj
            )
        {
            if (IsValid())
                (void)Cleanup(m_obj);

            m_obj = move(obj.m_obj);
            obj.m_obj = InvalidValue;

            return *this;
        }

        const 
        type_t&
        Get() const
        {
            return static_cast<type_t>(m_obj);
        }

        void
        Reset(
            __in const type_t& obj
            )
        {
            if (IsValid())
                (void)Cleanup(m_obj);

            m_obj = obj;
        }

        type_t&
        Release()
        {
            auto obj = m_obj;
            m_obj = nullptr;
            return obj;
        }
    };

    using SafeHandle = SafeObject<HANDLE, clean_fn::ClnCloseHandle, INVALID_HANDLE_VALUE>;
    using SafeLibrary = SafeObject<HMODULE, clean_fn::ClnFreeLibrary, nullptr>;
    using SafeLocal = SafeObject<HLOCAL, clean_fn::ClnLocalFree, nullptr>;
    using SafeGlobal = SafeObject<HGLOBAL, clean_fn::ClnGlobalFree, nullptr>;
    using SafeMapView = SafeObject<void*, clean_fn::ClnUnmapViewOfFile, nullptr>;
    using SafeDesktop = SafeObject<HDESK, clean_fn::ClnCloseDesktop, nullptr>;
    using SafeWindowStation = SafeObject<HWINSTA, clean_fn::ClnCloseWindowStation, nullptr>;
    using SafeService = SafeObject<SC_HANDLE, clean_fn::ClnCloseServiceHandle, nullptr>;
    using SafeVirtual = SafeObject<void*, clean_fn::ClnVirtualFree, nullptr>;
};
