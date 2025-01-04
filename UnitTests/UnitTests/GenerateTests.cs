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

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.GeneratePrivateKey(new MockStateManager(), parameterSet, true);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);
    }

    [TestMethod]
    public void GeneratePrivateKey_AfterPrivateKey()
    {
        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.GeneratePrivateKey(new MockStateManager(), XmssParameterSet.XMSS_SHA2_10_256, false);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);
        Assert.AreEqual(XmssParameterSet.XMSS_SHA2_10_256, xmss.ParameterSet);

        xmss.GeneratePrivateKey(new MockStateManager(), XmssParameterSet.XMSS_SHA2_16_256, false);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);
        Assert.AreEqual(XmssParameterSet.XMSS_SHA2_16_256, xmss.ParameterSet);
    }

    [TestMethod]
    public void GeneratePrivateKey_StoreStatelessFails()
    {
        var stateManager = new MockStateManager();
        using var xmss = new Xmss();

        stateManager.Setup();       // Load stateful (verify not exists)
        stateManager.Setup();       // Load stateless (verify not exists)
        stateManager.Setup();       // Purge
        stateManager.Setup(false);  // Store stateless

        Assert.ThrowsException<XmssStateManagerException>(() =>
        {
            xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);
        });
        Assert.IsFalse(xmss.HasPrivateKey);
    }

    [TestMethod]
    public void GeneratePrivateKey_StoreStatelessAndRollbackFail()
    {
        var stateManager = new MockStateManager();
        using var xmss = new Xmss();

        stateManager.Setup();       // Load stateful (verify not exists)
        stateManager.Setup();       // Load stateless (verify not exists)
        stateManager.Setup();       // Purge
        stateManager.Setup(false);  // Store stateless
        stateManager.Setup(false);  // Purge

        Assert.ThrowsException<AggregateException>(() =>
        {
            xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);
        });
        Assert.IsFalse(xmss.HasPrivateKey);
    }
}
