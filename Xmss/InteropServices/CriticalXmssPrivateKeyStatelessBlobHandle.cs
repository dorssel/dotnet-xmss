// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class CriticalXmssPrivateKeyStatelessBlobHandle : CriticalXmssPrivateBlobHandle<XmssPrivateKeyStatelessBlob>
{
    public static CriticalXmssPrivateKeyStatelessBlobHandle Alloc()
    {
        return Alloc<CriticalXmssPrivateKeyStatelessBlobHandle>(Defines.XMSS_PRIVATE_KEY_STATELESS_BLOB_SIZE);
    }
}
