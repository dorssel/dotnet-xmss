// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class Wots_Tests
{
    [TestMethod]
    [XmssReferenceDataSource("WOTS+")]
    public void KnownAnswerTest(XmssReferenceTestVector testVector)
    {
        // xmss-reference identifies the WOTS+ test vectors with an XMSS OID instead of a WOTS+ OID.
        using var wots = new Wots(XmssParameters.Lookup((XmssOid)testVector.Oid).WotsOID);

        var sk_seed = new byte[wots.Parameters.n];
        var pub_seed = new byte[wots.Parameters.n];

        var m = new byte[wots.Parameters.n];
        var addr = new uint[8];

        for (var i = 0u; i < 8; i++)
        {
            addr[i] = 500000000 * i;
        }

        for (var i = 0; i < wots.Parameters.n; i++)
        {
            m[i] = (byte)(3 * i);
            pub_seed[i] = (byte)(2 * i);
            sk_seed[i] = (byte)i;
        }

        var ADRS = unchecked(new Address()
        {
            layer_address = (int)addr[0],
            tree_address = (long)(((ulong)addr[1] << 32) | addr[2]),
            type = (AddressType)addr[3],
            OTS_address = (int)addr[4],
            chain_address = (int)addr[5],
            hash_address = (int)addr[6],
            keyAndMask = (int)addr[7],
        });

        var sk = wots.WOTS_genSK(sk_seed, pub_seed, ADRS);
        var pk = wots.WOTS_genPK(sk, pub_seed, ADRS);
        var sig = wots.WOTS_sign(sk, m, pub_seed, ADRS);
        var verify = wots.WOTS_pkFromSig(sig, m, pub_seed, ADRS);

        CollectionAssert.AreEqual(testVector.PublicKeyHash.ToArray(), XmssReferenceTestVector.computeHash(pk));
        CollectionAssert.AreEqual(testVector.SignatureHash.ToArray(), XmssReferenceTestVector.computeHash(sig));
        CollectionAssert.AreEqual(testVector.PublicKeyHash.ToArray(), XmssReferenceTestVector.computeHash(verify));
    }
}
