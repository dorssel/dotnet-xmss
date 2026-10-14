// SPDX-FileCopyrightText: 2026 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace FuzzingTests;

[TestClass]
sealed class Xmss_Tests
{
    public TestContext TestContext { get; set; }

    static readonly byte[] TestData = [1, 2, 3, 4];

    [TestMethod]
    public async Task Verify_ThreeByteMessagesDoNotMatchFourByteMessageSignature()
    {
        using var xmss = new Xmss();
        xmss.GeneratePrivateKey(null, XmssParameterSet.XMSS_SHA2_10_256, false);
        await xmss.CalculatePublicKeyAsync(null, TestContext.CancellationToken);

        var signature = xmss.Sign(TestData);
        // No 3-byte array should verify the signature, which was created for a 4-byte array.
        Prop.ForAll(Gen.ArrayOf(ArbMap.Default.GeneratorFor<byte>(), 3).ToArbitrary(),
            bytes => !xmss.Verify(bytes, signature)).QuickCheckThrowOnFailure();
    }
}
