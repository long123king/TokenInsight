#pragma once
#include "TypeDeclarations.h"
#include "TokenAccessor.hpp"

namespace CTokenFakeAPI
{
    static
    bool
    IsTokenRestricted(
      __in HANDLE TokenHandle
    )
    {
        CTokenRestrictedSids restricted_sids {CAccessToken(TokenHandle)};
        return restricted_sids.Count() > 0;
    }
};