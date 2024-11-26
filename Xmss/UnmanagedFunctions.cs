// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

static class UnmanagedFunctions
{
    [UnmanagedCallersOnly]
    public static unsafe void* Realloc(void* ptr, nuint size)
    {
        return NativeMemory.Realloc(ptr, size);
    }

    [UnmanagedCallersOnly]
    public static unsafe void Free(void* ptr)
    {
        NativeMemory.Free(ptr);
    }

    [UnmanagedCallersOnly]
    public static unsafe void Zeroize(void* ptr, nuint size)
    {
        CryptographicOperations.ZeroMemory(new(ptr, (int)size));
    }
}
