// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;

namespace Internal.UnitTests;

[TestClass]
sealed unsafe class VersionTests
{
    [TestMethod]
    public void XMSS_LIBRARY_VERSION_CONSTRUCT()
    {
        Assert.AreEqual(0x00123456u, Defines.XMSS_LIBRARY_VERSION_CONSTRUCT(0x12, 0x34, 0x56));
    }

    [TestMethod]
    public void XMSS_LIBRARY_VERSION()
    {
        _ = Defines.XMSS_LIBRARY_VERSION;
    }

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

    [TestMethod]
    public void ThrowIfVersionsNotEqual()
    {
        Xmss.ThrowIfVersionsNotEqual(Defines.XMSS_LIBRARY_VERSION, Defines.XMSS_LIBRARY_VERSION);
    }

    [TestMethod]
    public void ThrowIfVersionsNotEqual_Throws()
    {
        Assert.ThrowsException<DllNotFoundException>(() =>
        {
            Xmss.ThrowIfVersionsNotEqual(Defines.XMSS_LIBRARY_VERSION, uint.MaxValue);
        });
    }
}
