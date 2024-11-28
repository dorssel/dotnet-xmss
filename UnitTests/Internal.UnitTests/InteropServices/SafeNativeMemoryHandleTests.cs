// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using Dorssel.Security.Cryptography.InteropServices;

namespace Internal.UnitTests.InteropServices;

[TestClass]
sealed unsafe class SafeNativeMemoryHandleTests
{
    [TestMethod]
    public void AsRef_Valid()
    {
        using var nativeMemory = new SafeNativeMemoryHandle<int>();
        nativeMemory.AsPointerRef() = (int*)NativeMemory.Alloc(sizeof(int));

        nativeMemory.AsRef() = 42;
    }

    [TestMethod]
    public void AsRef_Null()
    {
        using var nativeMemory = new SafeNativeMemoryHandle<int>();

        _ = Assert.ThrowsException<NullReferenceException>(() =>
        {
            nativeMemory.AsRef() = 42;
        });
    }
}
