// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using Dorssel.Security.Cryptography.InteropServices;

namespace Internal.UnitTests.InteropServices.Generic;

[TestClass]
sealed unsafe class SafeNativeMemoryHandleGenericTests
{
    [TestMethod]
    public void TakeOwnership_Valid()
    {
        var nativeMemoryPointer = (int*)NativeMemory.Alloc(sizeof(int));
        using var nativeMemory = SafeNativeMemoryHandle.TakeOwnership(ref nativeMemoryPointer);

        Assert.IsFalse(nativeMemory.IsInvalid);
    }

    [TestMethod]
    public void TakeOwnership_Null()
    {
        int* nativeMemoryPointer = null;
        using var nativeMemory = SafeNativeMemoryHandle.TakeOwnership(ref nativeMemoryPointer);

        Assert.IsTrue(nativeMemory.IsInvalid);
    }

    [TestMethod]
    public void AsRef_Valid()
    {
        var nativeMemoryPointer = (int*)NativeMemory.Alloc(sizeof(int));
        using var nativeMemory = SafeNativeMemoryHandle.TakeOwnership(ref nativeMemoryPointer);

        nativeMemory.AsRef() = 42;
    }

    [TestMethod]
    public void AsRef_Null()
    {
        int* nativeMemoryPointer = null;
        using var nativeMemory = SafeNativeMemoryHandle.TakeOwnership(ref nativeMemoryPointer);

        _ = Assert.ThrowsException<NullReferenceException>(() =>
        {
            nativeMemory.AsRef() = 42;
        });
    }
}
