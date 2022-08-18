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

        // Test whether the default random number generator actually generates random keys:
        // a) when using XMSS_keyGen() twice on the same instance, and
        // b) when using XMSS_keyGen() once on two different instances.
        var (_, pk1_1) = xmss1.XMSS_keyGen();
        var (_, pk1_2) = xmss1.XMSS_keyGen();
        var (_, pk2_1) = xmss2.XMSS_keyGen();

        CollectionAssert.AreNotEqual(pk1_1.ToBytes(), pk1_2.ToBytes());
        CollectionAssert.AreNotEqual(pk1_1.ToBytes(), pk2_1.ToBytes());
        CollectionAssert.AreNotEqual(pk1_2.ToBytes(), pk2_1.ToBytes());
    }

    [TestMethod]
    [XmssReferenceDataSource("XMSS")]
    public void KnownAnswerTest(XmssReferenceTestVector testVector)
    {
        using var xmss = new Xmss((XmssOid)testVector.Oid);

        var m = new byte[1] { 37 };

        using var rng = new TestRandomNumberGenerator(Enumerable.Range(0, 3 * xmss.WotsParameters.n).Select(i => (byte)i).ToArray());
        var (sk, pk) = xmss.XMSS_keyGen(rng);

        sk.idx_sig = 1 << (xmss.Parameters.h - 1);

        var sig = xmss.XMSS_sign(m, sk);

        CollectionAssert.AreEqual(testVector.PublicKeyHash.ToArray(), XmssReferenceTestVector.computeHash(pk.ToBytes()));
        CollectionAssert.AreEqual(testVector.SignatureHash.ToArray(), XmssReferenceTestVector.computeHash(sig.ToBytes()));

        Assert.IsTrue(xmss.XMSS_verify(sig, m, pk));
    }
}
