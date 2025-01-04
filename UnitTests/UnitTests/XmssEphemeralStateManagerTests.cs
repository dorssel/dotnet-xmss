// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class XmssEphemeralStateManagerTests
{
    [TestMethod]
    public void Constructor()
    {
        _ = new XmssEphemeralStateManager();
    }

    [TestMethod]
    public void Store()
    {
        var stateManager = new XmssEphemeralStateManager();
        stateManager.Store(XmssKeyPart.Public, [1]);
    }

    [TestMethod]
    public void StoreStoreStatefulPart()
    {
        var stateManager = new XmssEphemeralStateManager();
        stateManager.Store(XmssKeyPart.PrivateStateful, [1]);

        stateManager.StoreStatefulPart([1], [2]);
    }

    [TestMethod]
    public void Load()
    {
        var data = new byte[] { 1, 2, 3 };

        var stateManager = new XmssEphemeralStateManager();
        stateManager.Store(XmssKeyPart.Public, data);

        var read = new byte[data.Length];

        Assert.ThrowsException<NotImplementedException>(() =>
        {
            stateManager.Load(XmssKeyPart.Public, read);
        });
    }

    [TestMethod]
    public void DeletePublicPart()
    {
        var stateManager = new XmssEphemeralStateManager();
        stateManager.Store(XmssKeyPart.Public, [1]);

        stateManager.DeletePublicPart();
    }

    [TestMethod]
    public void DeletePublicPart_NotExists()
    {
        var stateManager = new XmssEphemeralStateManager();

        stateManager.DeletePublicPart();
    }

    [TestMethod]
    public void Purge()
    {
        var stateManager = new XmssEphemeralStateManager();
        stateManager.Store(XmssKeyPart.PrivateStateless, [1]);
        stateManager.Store(XmssKeyPart.PrivateStateful, [2]);
        stateManager.Store(XmssKeyPart.Public, [3]);

        stateManager.Purge();
    }

    [TestMethod]
    public void Purge_NotExist()
    {
        var stateManager = new XmssEphemeralStateManager();

        stateManager.Purge();
    }

    [TestMethod]
    public async Task Use()
    {
        using var xmss = new Xmss();

        xmss.GeneratePrivateKey(new XmssEphemeralStateManager(), XmssParameterSet.XMSS_SHA2_10_256, false);
        await xmss.CalculatePublicKeyAsync();
        var message = new byte[] { 1, 2, 3 };
        var signature = xmss.Sign(message);

        Assert.IsTrue(xmss.Verify(message, signature));
    }
}
