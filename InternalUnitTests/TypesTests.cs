// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection.Metadata;
using Dorssel.Security.Cryptography.Internal;

namespace UnitTests;

[TestClass]
sealed unsafe class TypesTests
{
    [TestMethod]
    public void XMSS_TREE_DEPTH()
    {
        foreach (var parameter in Enum.GetValues<XmssParameterSetOID>())
        {
            Assert.IsTrue(Defines.XMSS_TREE_DEPTH(parameter) > 0);
        }
        Assert.AreEqual(0u, Defines.XMSS_TREE_DEPTH(0));
    }

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
