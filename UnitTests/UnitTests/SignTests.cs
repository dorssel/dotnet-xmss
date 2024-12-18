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

    [ClassCleanup(ClassCleanupBehavior.EndOfClass)]
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
        // oversized
        var signature = new byte[1024];

        Assert.ThrowsException<ArgumentException>(() =>
        {
            _ = Xmss.Sign([42], signature);
        });
    }
}
