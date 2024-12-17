// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class GenerateTests
{
    [TestMethod]
    public void GeneratePrivateKey()
    {
        using var xmss = new Xmss();
        xmss.GeneratePrivateKey(new MemoryStateManager(), XmssParameterSet.XMSS_SHA2_10_256, true);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);
    }

    [TestMethod]
    public async Task GeneratePublicKeyAsync()
    {
        using var xmss = new Xmss();
        xmss.GeneratePrivateKey(new MemoryStateManager(), XmssParameterSet.XMSS_SHA2_10_256, true);

        await xmss.GeneratePublicKeyAsync();

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }
}
