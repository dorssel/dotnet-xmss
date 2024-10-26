// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace UnitTests;

[TestClass]
sealed unsafe class VersionTests
{
    [TestMethod]
    public void XMSS_LIBRARY_GET_VERSION_MAJOR()
    {
        Assert.AreEqual(0x12, Defines.XMSS_LIBRARY_GET_VERSION_MAJOR(0x00123456));
    }

    [TestMethod]
    public void XMSS_LIBRARY_GET_VERSION_MINOR()
    {
        Assert.AreEqual(0x34, Defines.XMSS_LIBRARY_GET_VERSION_MINOR(0x00123456));
    }

    [TestMethod]
    public void XMSS_LIBRARY_GET_VERSION_PATCH()
    {
        Assert.AreEqual(0x56, Defines.XMSS_LIBRARY_GET_VERSION_PATCH(0x00123456));
    }
}
