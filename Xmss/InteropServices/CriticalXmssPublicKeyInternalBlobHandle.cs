// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class CriticalXmssPublicKeyInternalBlobHandle() : CriticalXmssBlobHandle<XmssPublicKeyInternalBlob>(false)
{
    public static CriticalXmssPublicKeyInternalBlobHandle Alloc(XmssCacheType cacheType, byte cacheLevel, XmssParameterSet parameterSet)
    {
        return Alloc<CriticalXmssPublicKeyInternalBlobHandle>(
            Defines.XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE(cacheType, cacheLevel, (XmssParameterSetOID)parameterSet));
    }
}
