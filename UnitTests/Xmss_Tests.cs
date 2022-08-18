// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class Xmss_Tests
{
    [TestMethod]
    public void XMSS_keyGen_DefaultRandomNumberGenerator()
    {
        using var xmss1 = new Xmss(XmssOid.XMSS_SHA2_10_256);
        using var xmss2 = new Xmss(XmssOid.XMSS_SHA2_10_256);

        // Test whether the default random number generator actually generates random keys;
        // both when using the XMSS_keyGen() twice on the same instance and once on two
        // different instances.
        var (_, pk1_1) = xmss1.XMSS_keyGen();
        var (_, pk1_2) = xmss1.XMSS_keyGen();
        var (_, pk2_1) = xmss2.XMSS_keyGen();

        Assert.IsFalse(pk1_1.ToBytes().SequenceEqual(pk1_2.ToBytes()));
        Assert.IsFalse(pk1_1.ToBytes().SequenceEqual(pk2_1.ToBytes()));
        Assert.IsFalse(pk1_2.ToBytes().SequenceEqual(pk2_1.ToBytes()));
    }

    [TestMethod]
    [XmssReferenceDataSource("XMSS")]
    public void KnownAnswerTest(XmssReferenceTestVector testVector)
    {
        var parameters = XmssParameters.Lookup((XmssOid)testVector.Oid);
        using var xmss = new Xmss(parameters.OID);

        var m = new byte[1] { 37 };

        using var rng = new TestRandomNumberGenerator(Enumerable.Range(0, 3 * parameters.Wots.n).Select(i => (byte)i).ToArray());
        var (sk, pk) = xmss.XMSS_keyGen(rng);

        sk.idx_sig = 1 << (parameters.h - 1);

        var sig = xmss.XMSS_sign(m, sk);

        Assert.IsTrue(testVector.PublicKeyHash.Span.SequenceEqual(XmssReferenceTestVector.computeHash(pk.ToBytes())));
        Assert.IsTrue(testVector.SignatureHash.Span.SequenceEqual(XmssReferenceTestVector.computeHash(sig.ToBytes())));

        Assert.IsTrue(xmss.XMSS_verify(sig, m, pk));
    }
}
