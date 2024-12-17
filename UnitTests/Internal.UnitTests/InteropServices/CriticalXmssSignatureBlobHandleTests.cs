// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.InteropServices;

namespace Internal.UnitTests.InteropServices;

[TestClass]
sealed class CriticalXmssSignatureBlobHandleTests
{
    [TestMethod]
    public void Constructor()
    {
        using var blob = new CriticalXmssSignatureBlobHandle();
    }
}
