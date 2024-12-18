// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class GenerateTests
{
    [TestMethod]
    [DataRow(XmssParameterSet.XMSS_SHA2_10_256)]
    [DataRow(XmssParameterSet.XMSS_SHA2_16_256)]
    [DataRow(XmssParameterSet.XMSS_SHA2_20_256)]
    [DataRow(XmssParameterSet.XMSS_SHAKE256_10_256)]
    [DataRow(XmssParameterSet.XMSS_SHAKE256_16_256)]
    [DataRow(XmssParameterSet.XMSS_SHAKE256_20_256)]
    public void GeneratePrivateKey(XmssParameterSet parameterSet)
    {
        using var xmss = new Xmss();
        xmss.GeneratePrivateKey(new MemoryStateManager(), parameterSet, true);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);
    }

    [TestMethod]
    public void GeneratePrivateKey_AfterPrivateKey()
    {
        using var xmss = new Xmss();
        xmss.GeneratePrivateKey(new MemoryStateManager(), XmssParameterSet.XMSS_SHA2_10_256, false);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);
        Assert.AreEqual(XmssParameterSet.XMSS_SHA2_10_256, xmss.ParameterSet);

        xmss.GeneratePrivateKey(new MemoryStateManager(), XmssParameterSet.XMSS_SHA2_16_256, false);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);
        Assert.AreEqual(XmssParameterSet.XMSS_SHA2_16_256, xmss.ParameterSet);
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
