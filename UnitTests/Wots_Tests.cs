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
        var sig = Wots.WOTS_sign(M, sk, SEED, ADRS);
        var tmp_pk = Wots.WOTS_pkFromSig(M, sig, SEED, ADRS);

        Assert.AreEqual(pk.Length, tmp_pk.Length);
        for (var i = 0; i < pk.Length; ++i)
        {
            Assert.IsTrue(Enumerable.SequenceEqual(pk[i], tmp_pk[i]));
        }
    }
}
