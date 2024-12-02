// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class SafeXmssPublicKeyInternalBlobHandle : SafeBlobHandle<XmssPublicKeyInternalBlob>
{
    public static SafeXmssPublicKeyInternalBlobHandle Alloc(XmssCacheType cacheType, byte cacheLevel, XmssParameterSet parameterSet)
    {
        return Alloc<SafeXmssPublicKeyInternalBlobHandle>(
            Defines.XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE(cacheType, cacheLevel, (XmssParameterSetOID)parameterSet));
    }
}
