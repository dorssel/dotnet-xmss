// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace Dorssel.Security.Cryptography.InteropServices;

abstract class CriticalXmssBlobHandle<T> : CriticalXmssHandle<T> where T : unmanaged
{
    protected static H Alloc<H>(int size) where H : CriticalXmssBlobHandle<T>, new()
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

    protected override unsafe void Free(T* pointer)
    {
        NativeMemory.Free(pointer);
    }
}
