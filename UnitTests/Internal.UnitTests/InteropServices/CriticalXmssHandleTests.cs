// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.InteropServices;

namespace Internal.UnitTests.InteropServices;

[TestClass]
sealed unsafe class CriticalXmssHandleTests
{
    [TestMethod]
    public void AsPointer()
    {
        using var blob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();

        Assert.IsTrue(blob.AsPointer() is not null);
    }

    [TestMethod]
    public void AsRef()
    {
        using var blob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();

        Assert.AreEqual(blob.DataLength, (int)blob.AsRef().data_size);
    }

    [TestMethod]
    public void AsPointerRef()
    {
        using var blob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();

        Assert.AreEqual(blob.DataLength, (int)blob.AsPointerRef()->data_size);
    }

    [TestMethod]
    public void SwapWith_ThisClosed()
    {
        using var blob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();
        using var other = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();

        other.Dispose();

        Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            blob.SwapWith(other);
        });
    }

    [TestMethod]
    public void SwapWith_OtherClosed()
    {
        using var blob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();
        using var other = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();

        other.Dispose();

        Assert.ThrowsException<ObjectDisposedException>(() =>
        {
            blob.SwapWith(other);
        });
    }
}
