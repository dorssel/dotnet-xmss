// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class VersionTests
{
    [TestMethod]
    public void NativeHeadersVersion()
    {
        using var xmss = new Xmss();

        Assert.AreEqual(Version.Parse("2.0.0"), xmss.NativeHeadersVersion);
    }

    [TestMethod]
    public void NativeLibraryVersion()
    {
        using var xmss = new Xmss();

        Assert.AreEqual(Version.Parse("2.0.0"), xmss.NativeLibraryVersion);
    }
}
