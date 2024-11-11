// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class SafeSigningContextHandle
    : SafeHandle
{
    public unsafe SafeSigningContextHandle(XmssSigningContext* signingContext, bool ownsHandle)
        : base(0, ownsHandle)
    {
        SetHandle((nint)signingContext);
    }

    public static unsafe SafeSigningContextHandle TakeOwnership(ref XmssSigningContext* ptr)
    {
        var result = new SafeSigningContextHandle(ptr, true);
        ptr = null;
        return result;
    }

    public ref XmssSigningContext AsRef()
    {
        unsafe
        {
            return ref *(XmssSigningContext*)handle;
        }
    }

    public override bool IsInvalid => handle == 0;

    protected override bool ReleaseHandle()
    {
        unsafe
        {
            UnsafeNativeMethods.xmss_free_signing_context((XmssSigningContext*)handle);
        }
        return true;
    }
}
