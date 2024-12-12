// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class CriticalXmssSigningContextHandle : CriticalXmssHandle<XmssSigningContext>
{
    protected override unsafe void Free(XmssSigningContext* pointer)
    {
        UnsafeNativeMethods.xmss_free_signing_context(pointer);
    }
}
