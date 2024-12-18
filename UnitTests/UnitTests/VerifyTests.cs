// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class VerifyTests
{
    static readonly byte[] Message = [42];
    static byte[] PublicKey = [];
    static byte[] Signature = [];

    [ClassInitialize]
    public static async Task ClassInitialize(TestContext testContext)
    {
        _ = testContext;

        using var xmss = new Xmss();
        xmss.GeneratePrivateKey(new MemoryStateManager(), XmssParameterSet.XMSS_SHA2_10_256, true);
        await xmss.GeneratePublicKeyAsync();

        PublicKey = xmss.ExportRfcPublicKey();
        Signature = xmss.Sign(Message);
    }

    [TestMethod]
    public void Verify()
    {
        using var xmss = new Xmss();
        xmss.ImportRfcPublicKey(PublicKey, out _);

        Assert.IsTrue(xmss.Verify(Message, Signature));
    }

    [TestMethod]
    public void VerifyStream()
    {
        using var xmss = new Xmss();
        xmss.ImportRfcPublicKey(PublicKey, out _);

        using var stream = new MemoryStream(Message);
        Assert.IsTrue(xmss.Verify(stream, Signature));
    }
}
