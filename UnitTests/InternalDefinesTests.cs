// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace UnitTests;

[TestClass]
sealed unsafe class InternalDefinesTests
{
    [TestMethod]
    public void XMSS_VALUE_256_WORDS()
    {
        Assert.AreEqual(sizeof(XmssValue256) / sizeof(uint), Defines.XMSS_VALUE_256_WORDS);
    }

    [TestMethod]
    public void Value256Consistency()
    {
        Assert.AreEqual(sizeof(XmssValue256), sizeof(XmssNativeValue256));
    }
}
