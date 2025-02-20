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
        xmss.GeneratePrivateKey(new MockStateManager(), XmssParameterSet.XMSS_SHA2_10_256, true);
        await xmss.CalculatePublicKeyAsync();

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
    public void Verify_NoKey()
    {
        using var xmss = new Xmss();

        Assert.ThrowsExactly<InvalidOperationException>(() =>
        {
            _ = xmss.Verify(Message, Signature);
        });
    }

    [TestMethod]
    public void Verify_SignatureWrongLength()
    {
        using var xmss = new Xmss();
        xmss.ImportRfcPublicKey(PublicKey, out _);

        Assert.IsFalse(xmss.Verify(Message, Signature[..^1].AsSpan()));
    }

    [TestMethod]
    public void Verify_SignatureInvalid()
    {
        using var xmss = new Xmss();
        xmss.ImportRfcPublicKey(PublicKey, out _);

        Assert.IsFalse(xmss.Verify([.. Message, 1], Signature));
    }

    [TestMethod]
    public void VerifyStream()
    {
        using var xmss = new Xmss();
        xmss.ImportRfcPublicKey(PublicKey, out _);

        using var stream = new MemoryStream(Message);
        Assert.IsTrue(xmss.Verify(stream, Signature));
    }

    [TestMethod]
    public void VerifyStream_SignatureWrongLength()
    {
        using var xmss = new Xmss();
        xmss.ImportRfcPublicKey(PublicKey, out _);

        using var stream = new MemoryStream(Message);
        Assert.IsFalse(xmss.Verify(stream, Signature[..^1].AsSpan()));
    }

    [TestMethod]
    public void VerifyStream_SignatureInvalid()
    {
        using var xmss = new Xmss();
        xmss.ImportRfcPublicKey(PublicKey, out _);

        using var stream = new MemoryStream([.. Message, 1]);
        Assert.IsFalse(xmss.Verify(stream, Signature));
    }
}
