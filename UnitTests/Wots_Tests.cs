// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class Wots_Tests
{
    [TestMethod]
    public void OidMapping()
    {
        // xmss-reference identifies the WOTS+ test vectors with an XMSS OID instead of a WOTS+ OID.
        // They expect a mapping where each 3 successive XMSS OIDs (one for tree height 10, 16, and 20) per
        // WOTS+ OID.
        //
        // This test asserts that assumption.

        foreach (var oid in Enum.GetValues<XmssOid>())
        {
            var parameters = XmssParameters.Lookup(oid);
            Assert.AreEqual(parameters.Wots.OID, (WotsOid)((((int)parameters.OID) - 1) / 3 + 1));
        }
    }

    [TestMethod]
    [XmssReferenceDataSource("WOTS+")]
    public void KnownAnswerTest(XmssReferenceTestVector testVector)
    {
        var parameters = XmssParameters.Lookup((XmssOid)testVector.Oid).Wots;
        using var wots = new Wots(parameters.OID);

        var sk_seed = new byte[parameters.n];
        var pub_seed = new byte[parameters.n];

        var m = new byte[parameters.n];
        var addr = new uint[8];

        for (var i = 0u; i < 8; i++)
        {
            addr[i] = 500000000 * i;
        }

        for (var i = 0; i < parameters.n; i++)
        {
            m[i] = (byte)(3 * i);
            pub_seed[i] = (byte)(2 * i);
            sk_seed[i] = (byte)i;
        }

        var ADRS = new Address()
        {
            layer_address = (int)addr[0],
            tree_address = (long)(((ulong)addr[1] << 32) | addr[2]),
            type = (AddressType)addr[3],
            OTS_address = (int)addr[4],
            chain_address = (int)addr[5],
            hash_address = (int)addr[6],
            keyAndMask = (int)addr[7],
        };

        var sk = wots.WOTS_genSK(sk_seed, pub_seed, ADRS);
        var pk = wots.WOTS_genPK(sk, pub_seed, ADRS);
        var sig = wots.WOTS_sign(sk, m, pub_seed, ADRS);
        var verify = wots.WOTS_pkFromSig(sig, m, pub_seed, ADRS);

        Assert.IsTrue(testVector.PublicKeyHash.Span.SequenceEqual(XmssReferenceTestVector.computeHash(pk)));
        Assert.IsTrue(testVector.SignatureHash.Span.SequenceEqual(XmssReferenceTestVector.computeHash(sig)));
        Assert.IsTrue(testVector.PublicKeyHash.Span.SequenceEqual(XmssReferenceTestVector.computeHash(verify)));
    }
}
