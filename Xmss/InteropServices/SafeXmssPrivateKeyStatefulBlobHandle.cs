// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class SafeXmssPrivateKeyStatefulBlobHandle : SafeBlobHandle<XmssPrivateKeyStatefulBlob>
{
    public static SafeXmssPrivateKeyStatefulBlobHandle Alloc()
    {
        return Alloc<SafeXmssPrivateKeyStatefulBlobHandle>(Defines.XMSS_PRIVATE_KEY_STATEFUL_BLOB_SIZE);
    }
}
