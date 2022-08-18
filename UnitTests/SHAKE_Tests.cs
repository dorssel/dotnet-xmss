// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class SHAKE_Tests
{
    [TestMethod]
    public void Constructor_InvalidBitSizeThrows()
    {
        Assert.ThrowsException<ArgumentException>(() => new SHAKE(42, 128));
    }

    [TestMethod]
    [NistShakeMsgDataSource]
    public void NistTestVector(NistShakeMsgTestVector testVector)
    {
        using var shake = new SHAKE(testVector.L, testVector.Output.Length * 8);
        var output = shake.ComputeHash(testVector.Msg.ToArray());
        CollectionAssert.AreEqual(testVector.Output.ToArray(), output);
    }
}
