// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class Wots_Tests
{
    [TestMethod]
    public void TestAll()
    {
        var M = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();

        var sk = Wots.WOTS_genSK();
        var ADRS = new Address();
        var SEED = Enumerable.Range(42, 32).Select(i => (byte)i).ToArray();
        var pk = Wots.WOTS_genPK(sk, SEED, ADRS);
        var sig = Wots.WOTS_sign(sk, M, SEED, ADRS);
        var tmp_pk = Wots.WOTS_pkFromSig(sig, M, SEED, ADRS);

        Assert.AreEqual(pk.Length, tmp_pk.Length);
        for (var i = 0; i < pk.Length; ++i)
        {
            Assert.IsTrue(Enumerable.SequenceEqual(pk[i], tmp_pk[i]));
        }
    }

    /*

WOTS+ 1 a5df5a7785a48961552e 4443fb313e5b0c2e8bec fc27066a9b31c0069597
WOTS+ 4 b60e1297f5c9b328c5e8 3ae3de6598456112261d 1ae375ab3af144099b3d
WOTS+ 7 654c7f6754b55312197f a51bd20ef66e93d79464 70dac71617da61947011
WOTS+ 10 e7462d29751df96bf5a4 ffb59bc9bf87e4e4b7f0 0cf456d0f4b02b341e12
WOTS+ 13 adbec5b9ba94bff3447d b32683d5888df51aa074 58eb225e44f38082b356
WOTS+ 16 e008635b776020636868 05d9a9d517021307b1a7 2ed530d278acdf27e01d
WOTS+ 19 8f041a7c67b46fc80b0d 98a906af2d18429309f6 34457720369d5f7691e9
XMSSMT 2 9df4c75282451bf2bc53 fd4ff4c18801147b2804
XMSSMT 10 fdeb0cc4fed643bf70ce fbeb33a7aed7af7ea526
XMSSMT 18 dbe6fc388fbd610b3401 2c2a66cae9a16414088d
XMSSMT 26 3739e7d3668932d9ca44 ec8d62bb9d4ba74c6729
XMSSMT 34 eef50cfa8f267939ad08 759e579a56097da369b5
XMSSMT 42 2d6ae135fda1077788ca 09a73575932668ca5e8d
XMSSMT 50 21d799da214da955d915 45f8be8e21f1af08c828
XMSS 1 7de72d192121f414d4bb 8b6cb278d50a3694ca38
XMSS 4 74ee7c42b4e42a424ed9 b9e63b0376a550eabe1b
XMSS 7 764614ee2ce5e4bf0114 3e9035cffa0fd4be98bd
XMSS 10 e47fe831b6ee463e2881 ce2dc09cd7ad8c87ae06
XMSS 13 5933d4b1e696804718c7 6ec9da2e05da544d9c5d
XMSS 16 cef3d38791d56efee1b3 9939a0f87502df5d1e31
XMSS 19 7fa280e502275858b27b 7782c54424c9ca082926

    */

    static string getHashText(params byte[][] buf)
    {
        var shake = new Waher.Security.SHA3.SHAKE128(80 /* bits */);
        var hash = shake.ComputeVariable(buf.SelectMany(i => i).ToArray());
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }

    [TestMethod]
    public void TestKAT()
    {
        const string expected = "WOTS+ 1 a5df5a7785a48961552e 4443fb313e5b0c2e8bec fc27066a9b31c0069597";

        const int n = 32;
        const int len = 67;

        var sk_seed = new byte[n];
        var pub_seed = new byte[n];

        var m = new byte[n];
        var addr = new uint[8];
        var addr2 = new uint[8];

        for (var i = 0u; i < 8; i++)
        {
            addr[i] = 500000000 * i;
            addr2[i] = 400000000 * i;
        }

        for (var i = 0; i < n; i++)
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

        var ADRS2 = new Address()
        {
            layer_address = (int)addr2[0],
            tree_address = (long)(((ulong)addr2[1] << 32) | addr2[2]),
            type = (AddressType)addr2[3],
            OTS_address = (int)addr2[4],
            chain_address = (int)addr2[5],
            hash_address = (int)addr2[6],
            keyAndMask = (int)addr2[7],
        };

        ADRS.hash_address = 0;
        ADRS.keyAndMask = 0;
        var sk = new byte[len][];
        for (var j = 0; j < len; j++)
        {
            ADRS.chain_address = j;
            sk[j] = XmssPrivateKey.PRF_keygen(sk_seed, pub_seed, ADRS);
        }

        var pk = Wots.WOTS_genPK(sk, pub_seed, ADRS);
        var sig = Wots.WOTS_sign(sk, m, pub_seed, ADRS);

        byte[] leaf;
        {
            // NOTE: This "tests" an internal xmss-reference function (gen_leef_wots), which
            // we don't have (as it is an implementation detail of xmss-reference, not a standard).
            // We include it for completeness.

            ADRS2.hash_address = 0;
            ADRS2.keyAndMask = 0;
            var sk2 = new byte[len][];
            for (var j = 0; j < len; j++)
            {
                ADRS2.chain_address = j;
                sk2[j] = XmssPrivateKey.PRF_keygen(sk_seed, pub_seed, ADRS2);
            }
            var pk2 = Wots.WOTS_genPK(sk2, pub_seed, ADRS2);
            leaf = Xmss.ltree(pk2, pub_seed, ADRS);
        }

        var result = $"WOTS+ 1 {getHashText(pk)} {getHashText(sig)} {getHashText(leaf)}";

        Assert.AreEqual(expected, result);
    }
}
