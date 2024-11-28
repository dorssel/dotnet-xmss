// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace Dorssel.Security.Cryptography.InteropServices;

abstract class SafeXmssHandle<T> : SafeHandle where T : unmanaged
{
    public unsafe SafeXmssHandle()
        : base(0, true)
    {
    }

    GCHandle Pin;

    public void Unpin()
    {
        if (Pin.IsAllocated)
        {
            Pin.Free();
        }
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Unpin();
    }

    public ref T AsRef()
    {
        ObjectDisposedException.ThrowIf(IsClosed, this);
        unsafe
        {
            return ref *(T*)handle;
        }
    }

    public unsafe ref T* AsPointerRef()
    {
        ObjectDisposedException.ThrowIf(IsClosed, this);
        if (!Pin.IsAllocated)
        {
            Pin = GCHandle.Alloc(this);
        }
        fixed (nint* handlePtr = &handle)
        {
            return ref *(T**)handlePtr;
        }
    }

    public sealed override bool IsInvalid => handle == 0;

    protected abstract unsafe void Free(T* pointer);

    protected sealed override bool ReleaseHandle()
    {
        unsafe
        {
            Free((T*)handle);
        }
        return true;
    }
}
