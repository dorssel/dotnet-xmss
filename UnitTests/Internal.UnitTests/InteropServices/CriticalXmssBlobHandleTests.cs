// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;
using Dorssel.Security.Cryptography.InteropServices;

namespace Internal.UnitTests.InteropServices;

[TestClass]
sealed unsafe class CriticalXmssBlobHandleTests
{
    [TestMethod]
    public void DataLength()
    {
        using var blob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();

        Assert.AreEqual(Defines.XMSS_PRIVATE_KEY_STATEFUL_BLOB_SIZE, sizeof(nint) + blob.DataLength);
    }

    [TestMethod]
    public void Data()
    {
        using var blob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();

        Assert.AreEqual(blob.DataLength, blob.Data.Length);
    }
}
