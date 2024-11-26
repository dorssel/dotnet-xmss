// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;
using Dorssel.Security.Cryptography.InteropServices;

namespace Internal.UnitTests.InteropServices;

[TestClass]
sealed unsafe class SafeSigningContextHandleTests
{
    static unsafe XmssSigningContext* CreateSigningContextPointer()
    {
        XmssSigningContext* signingContext = null;
        var result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext, XmssParameterSetOID.XMSS_PARAM_SHA2_10_256,
            &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        return signingContext;
    }

    [TestMethod]
    public void TakeOwnership_Valid()
    {
        var signingContextPointer = CreateSigningContextPointer();
        using var sigingContext = SafeSigningContextHandle.TakeOwnership(ref signingContextPointer);

        Assert.IsFalse(sigingContext.IsInvalid);
    }

    [TestMethod]
    public void TakeOwnership_Null()
    {
        XmssSigningContext* signingContextPointer = null;
        using var sigingContext = SafeSigningContextHandle.TakeOwnership(ref signingContextPointer);

        Assert.IsTrue(sigingContext.IsInvalid);
    }

    [TestMethod]
    public void AsRef_Valid()
    {
        var signingContextPointer = CreateSigningContextPointer();
        using var sigingContext = SafeSigningContextHandle.TakeOwnership(ref signingContextPointer);

        _ = sigingContext.AsRef().ToString();
    }

    [TestMethod]
    public void AsRef_Null()
    {
        XmssSigningContext* signingContextPointer = null;
        using var sigingContext = SafeSigningContextHandle.TakeOwnership(ref signingContextPointer);

        _ = Assert.ThrowsException<NullReferenceException>(() =>
        {
            _ = sigingContext.AsRef().ToString();
        });
    }
}
