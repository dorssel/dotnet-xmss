// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography;

sealed class SafeSigningContext
    : IDisposable
{
    byte[] Data;
    GCHandle DataHandle;

    public SafeSigningContext()
    {
        Data = new byte[Defines.XMSS_SIGNING_CONTEXT_SIZE];
        DataHandle = GCHandle.Alloc(Data, GCHandleType.Pinned);
    }

    public static unsafe implicit operator XmssSigningContext*(SafeSigningContext safeSigningContext)
        => (XmssSigningContext*)safeSigningContext.DataHandle.AddrOfPinnedObject();

    public void Dispose()
    {
        DataHandle.Free();
    }
}
