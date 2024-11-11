﻿// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace Dorssel.Security.Cryptography.InteropServices;

class SafeNativeMemoryHandle
    : SafeHandle
{
    public unsafe SafeNativeMemoryHandle(void* ptr, bool ownsHandle)
        : base(0, ownsHandle)
    {
        SetHandle((nint)ptr);
    }

    public static unsafe SafeNativeMemoryHandle<T> TakeOwnership<T>(ref T* ptr) where T : unmanaged
    {
        var result = new SafeNativeMemoryHandle<T>(ptr, true);
        ptr = null;
        return result;
    }

    public override bool IsInvalid => handle == 0;

    protected override bool ReleaseHandle()
    {
        unsafe
        {
            NativeMemory.Free((void*)handle);
        }
        return true;
    }
}

sealed class SafeNativeMemoryHandle<T>
    : SafeNativeMemoryHandle
    where T : unmanaged
{
    public unsafe SafeNativeMemoryHandle(T* ptr, bool ownsHandle)
        : base(ptr, ownsHandle)
    {
    }

    public ref T AsRef()
    {
        unsafe
        {
            return ref *(T*)handle;
        }
    }
}
