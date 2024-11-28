// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed unsafe class SafeNativeMemoryHandle<T>() : SafeXmssHandle<T>() where T : unmanaged
{
    protected override unsafe void Free(T* pointer)
    {
        NativeMemory.Free(pointer);
    }
}
