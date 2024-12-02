// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class SafeXmssPrivateKeyStatelessBlobHandle : SafeBlobHandle<XmssPrivateKeyStatelessBlob>
{
    public static SafeXmssPrivateKeyStatelessBlobHandle Alloc()
    {
        return Alloc<SafeXmssPrivateKeyStatelessBlobHandle>(Defines.XMSS_PRIVATE_KEY_STATELESS_BLOB_SIZE);
    }
}
