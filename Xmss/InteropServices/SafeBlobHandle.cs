// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace Dorssel.Security.Cryptography.InteropServices;

abstract class SafeBlobHandle<T> : SafeNativeMemoryHandle<T> where T : unmanaged
{
    protected static H Alloc<H>(int size) where H : SafeBlobHandle<T>, new()
    {
        var result = new H();
        unsafe
        {
            result.AsPointerRef() = (T*)NativeMemory.Alloc((nuint)size);
            *(nuint*)result.AsPointer() = (nuint)(size - sizeof(nuint));
        }
        return result;
    }

    public int DataLength
    {
        get
        {
            unsafe
            {
                return (int)*(nuint*)AsPointer();
            }
        }
    }

    public Span<byte> Data
    {
        get
        {
            unsafe
            {
                return new((nuint*)AsPointer() + 1, DataLength);
            }
        }
    }
}
