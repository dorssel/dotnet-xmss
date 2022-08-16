// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class Wots_Tests
{
    static byte[] getHash(params byte[][] buf)
    {
        using var shake = new SHAKE(128, 80);
        return shake.ComputeHash(buf.SelectMany(i => i).ToArray());
    }

    [TestMethod]
    [XmssReferenceDataSource("WOTS+")]
    public void TestKAT(XmssReferenceTestVector testVector)
    {
        var parameters = WotsParameters.Lookup(((XmssOid)testVector.Oid).ToWotsOid());
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

        Assert.IsTrue(Enumerable.SequenceEqual(testVector.PublicKeyHash.ToArray(), getHash(pk)));
        Assert.IsTrue(Enumerable.SequenceEqual(testVector.SignatureHash.ToArray(), getHash(sig)));
        Assert.IsTrue(Enumerable.SequenceEqual(testVector.PublicKeyHash.ToArray(), getHash(verify)));
    }
}
