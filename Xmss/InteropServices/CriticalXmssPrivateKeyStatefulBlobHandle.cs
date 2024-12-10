// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class CriticalXmssPrivateKeyStatefulBlobHandle() : CriticalXmssBlobHandle<XmssPrivateKeyStatefulBlob>(true)
{
    public static CriticalXmssPrivateKeyStatefulBlobHandle Alloc()
    {
        return Alloc<CriticalXmssPrivateKeyStatefulBlobHandle>(Defines.XMSS_PRIVATE_KEY_STATEFUL_BLOB_SIZE);
    }
}
