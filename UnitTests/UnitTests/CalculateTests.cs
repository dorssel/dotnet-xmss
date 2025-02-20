// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class CalculateTests
{
    [TestMethod]
    public async Task CalculatePublicKeyAsync_Ephemeral_AndSign()
    {
        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.GeneratePrivateKey(null, XmssParameterSet.XMSS_SHA2_10_256, true);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        await xmss.CalculatePublicKeyAsync();

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);

        _ = xmss.Sign([1, 2, 3]);
    }

    [TestMethod]
    public async Task CalculatePublicKeyAsync_AndImport()
    {
        var stateManager = new MockStateManager();

        // generate
        {
            using var xmss = new Xmss();

            Assert.IsFalse(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, true);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            await xmss.CalculatePublicKeyAsync();

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsTrue(xmss.HasPublicKey);
        }

        // import
        {
            using var xmss = new Xmss();

            Assert.IsFalse(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            xmss.ImportPrivateKey(stateManager);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsTrue(xmss.HasPublicKey);
        }
    }

    [TestMethod]
    public async Task CalculatePublicKeyAsync_Report_AndGenerateAgain()
    {
        var stateManager = new MockStateManager();

        // generate
        {
            using var xmss = new Xmss();

            Assert.IsFalse(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, true);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            var lastPercentage = 0.0;
            await xmss.CalculatePublicKeyAsync((percentage) =>
            {
                Assert.IsTrue(percentage > lastPercentage);
                lastPercentage = percentage;
            });
            Assert.AreEqual(100.0, lastPercentage);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsTrue(xmss.HasPublicKey);

            await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            {
                await xmss.CalculatePublicKeyAsync();
            });
        }
    }

    [TestMethod]
    public async Task CalculatePublicKeyAsync_DeletePublicFails()
    {
        var stateManager = new MockStateManager();

        // generate
        {
            using var xmss = new Xmss();

            Assert.IsFalse(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, true);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            stateManager.Setup(false);  // DeletePublicPart

            await Assert.ThrowsExactlyAsync<XmssStateManagerException>(async () =>
            {
                await xmss.CalculatePublicKeyAsync();
            });

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsTrue(xmss.HasPublicKey);
        }

        // import
        {
            using var xmss = new Xmss();

            Assert.IsFalse(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            xmss.ImportPrivateKey(stateManager);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);
        }
    }
}
