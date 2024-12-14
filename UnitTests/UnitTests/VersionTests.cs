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
        Assert.AreEqual(Version.Parse("2.0.0"), Xmss.NativeHeadersVersion);
    }

    [TestMethod]
    public void NativeLibraryVersion()
    {
        Assert.AreEqual(Version.Parse("2.0.0"), Xmss.NativeLibraryVersion);
    }
}
