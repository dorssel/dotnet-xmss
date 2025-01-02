// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography.InteropServices;

abstract class CriticalXmssPrivateBlobHandle<T> : CriticalXmssBlobHandle<T> where T : unmanaged
{
    protected sealed override unsafe void Free(T* pointer)
    {
        // cannot use Data and DataLength, as object is marked as closed already
        CryptographicOperations.ZeroMemory(new((nuint*)handle + 1, (int)*(nuint*)handle));
        base.Free(pointer);
    }
}
