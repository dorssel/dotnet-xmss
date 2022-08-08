// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class Xmss_Tests
{
    [TestMethod]
    public void TestAll()
    {
        var M = Enumerable.Range(0, 2000).Select(i => (byte)(i & 0xff)).ToArray();

        var (SK, PK) = Xmss.XMSS_keyGen();
        var Sig = Xmss.XMSS_sign(M, SK);
        Assert.IsTrue(Xmss.XMSS_verify(Sig, M, PK));
    }
}
