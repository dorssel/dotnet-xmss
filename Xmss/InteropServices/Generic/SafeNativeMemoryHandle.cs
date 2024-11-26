// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography.InteropServices.Generic;

sealed unsafe class SafeNativeMemoryHandle<T>(T* ptr, bool ownsHandle)
    : SafeNativeMemoryHandle(ptr, ownsHandle)
    where T : unmanaged
{
    public ref T AsRef()
    {
        unsafe
        {
            return ref *(T*)handle;
        }
    }
}
