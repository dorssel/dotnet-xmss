// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Xmss;
using NativeHelper;
using System.Buffers.Binary;

namespace UnitTests;

[TestClass]
public class NativeTests
{
    [AssemblyInitialize]
    public static void AssemblyInitialize(TestContext testContext)
    {
        _ = testContext;
        NativeLoader.Setup();
    }

    [TestMethod]
    public void LibraryGetVersionMatchesExpected()
    {
        var version = Native.LibraryGetVersion();

        Assert.AreEqual(0x00020000u, version);
    }

    [TestMethod]
    public void VerificationInitValid()
    {
        Native.XmssPublicKey publicKey;
        var signature = new uint[625];

        var schemeIdentifier = 1u; // XMSS_PARAM_SHA2_10_256
        publicKey.scheme_identifier = BitConverter.IsLittleEndian
            ? BinaryPrimitives.ReverseEndianness(schemeIdentifier)
            : schemeIdentifier;

        var result = Native.VerificationInit(out var context, in publicKey, signature);
        result = Native.VerificationUpdate(ref context, [1, 2, 3, 4, 5,]);
        result = Native.VerificationCheck(ref context, in publicKey);
    }
}
