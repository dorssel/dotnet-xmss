// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class SafeKeyContextHandle
    : SafeHandle
{
    public unsafe SafeKeyContextHandle(XmssKeyContext* keyContext, bool ownsHandle)
        : base(0, ownsHandle)
    {
        SetHandle((nint)keyContext);
    }

    public static unsafe SafeKeyContextHandle TakeOwnership(ref XmssKeyContext* ptr)
    {
        var result = new SafeKeyContextHandle(ptr, true);
        ptr = null;
        return result;
    }

    public override bool IsInvalid => handle == 0;

    protected override bool ReleaseHandle()
    {
        unsafe
        {
            UnsafeNativeMethods.xmss_free_key_context((XmssKeyContext*)handle);
        }
        return true;
    }
}
