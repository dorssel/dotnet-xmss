// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class CriticalXmssKeyContextHandle : CriticalXmssHandle<XmssKeyContext>
{
    protected override unsafe void Free(XmssKeyContext* pointer)
    {
        UnsafeNativeMethods.xmss_free_key_context(pointer);
    }
}
