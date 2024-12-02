// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace Dorssel.Security.Cryptography.InteropServices;

abstract class SafeNativeMemoryHandle<T> : SafeXmssHandle<T> where T : unmanaged
{
    protected sealed override unsafe void Free(T* pointer)
    {
        NativeMemory.Free(pointer);
    }
}
