// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.InteropServices;

namespace Internal.UnitTests.InteropServices;

[TestClass]
sealed class CriticalXmssPrivateKeyStatefulBlobHandleTests
{
    [TestMethod]
    public void Alloc()
    {
        using var blob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();
    }
}
