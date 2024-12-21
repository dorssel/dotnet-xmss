// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
[DoNotParallelize]
sealed class SignTests
{
    static readonly Xmss Xmss = new();

    [ClassInitialize]
    public static async Task ClassInitialize(TestContext testContext)
    {
        _ = testContext;

        Xmss.GeneratePrivateKey(new MemoryStateManager(), XmssParameterSet.XMSS_SHA2_10_256, true);
        await Xmss.GeneratePublicKeyAsync();
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        Xmss.Dispose();
    }

    [TestMethod]
    public void Sign()
    {
        _ = Xmss.Sign([42]);
    }

    [TestMethod]
    public void Sign_NoKey()
    {
        using var xmss = new Xmss();

        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            _ = xmss.Sign([42]);
        });
    }

    [TestMethod]
    public void Sign_Destination()
    {
        // oversized
        var signature = new byte[4096];

        var bytesWritten = Xmss.Sign([42], signature);

        Assert.IsTrue(bytesWritten > 0);
        Assert.IsTrue(bytesWritten < signature.Length);
    }

    [TestMethod]
    public void Sign_Destination_TooShort()
    {
        // undersized
        var signature = new byte[1024];

        Assert.ThrowsException<ArgumentException>(() =>
        {
            _ = Xmss.Sign([42], signature);
        });
    }

    [TestMethod]
    public unsafe void SignLarge()
    {
        byte message = 42;
        _ = Xmss.Sign(&message, 1);
    }

    [TestMethod]
    public unsafe void SignLarge_Destination()
    {
        // oversized
        var signature = new byte[4096];

        byte message = 42;
        var bytesWritten = Xmss.Sign(&message, 1, signature);

        Assert.IsTrue(bytesWritten > 0);
        Assert.IsTrue(bytesWritten < signature.Length);
    }

    [TestMethod]
    public unsafe void SignLarge_Destination_TooShort()
    {
        // undersized
        var signature = new byte[1024];

        Assert.ThrowsException<ArgumentException>(() =>
        {
            byte message = 42;
            _ = Xmss.Sign(&message, 1, signature);
        });
    }

    [TestMethod]
    public unsafe void SignLarge_Null()
    {
        Assert.ThrowsException<ArgumentNullException>(() =>
        {
            _ = Xmss.Sign(null, 1);
        });
    }

    [TestMethod]
    public void SignaturesRemaining()
    {
        var oldCount = Xmss.SignaturesRemaining;
        _ = Xmss.Sign([42]);
        var newCount = Xmss.SignaturesRemaining;

        Assert.AreEqual(oldCount - 1, newCount);
    }

    [TestMethod]
    public void RequestFutureSignatures()
    {
        var oldCount = Xmss.SignaturesRemaining;
        Xmss.RequestFutureSignatures(2);
        _ = Xmss.Sign([42]);
        var newCount = Xmss.SignaturesRemaining;

        Assert.AreEqual(oldCount - 2, newCount);

        _ = Xmss.Sign([42]);
        newCount = Xmss.SignaturesRemaining;

        Assert.AreEqual(oldCount - 2, newCount);

        _ = Xmss.Sign([42]);
        newCount = Xmss.SignaturesRemaining;

        Assert.AreEqual(oldCount - 3, newCount);
    }
}
