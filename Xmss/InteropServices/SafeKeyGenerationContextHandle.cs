// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class SafeKeyGenerationContextHandle : SafeXmssHandle<XmssKeyGenerationContext>
{
    protected override unsafe void Free(XmssKeyGenerationContext* pointer)
    {
        UnsafeNativeMethods.xmss_free_key_generation_context(pointer);
    }
}
