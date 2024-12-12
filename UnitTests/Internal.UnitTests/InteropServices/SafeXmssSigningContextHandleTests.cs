// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;
using Dorssel.Security.Cryptography.InteropServices;

namespace Internal.UnitTests.InteropServices;

[TestClass]
sealed unsafe class SafeXmssSigningContextHandleTests
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
    public void AsRef_Valid()
    {
        using var sigingContext = new CriticalXmssSigningContextHandle();
        sigingContext.AsPointerRef() = CreateSigningContextPointer();

        _ = sigingContext.AsRef().ToString();
    }

    [TestMethod]
    public void AsRef_Null()
    {
        using var sigingContext = new CriticalXmssSigningContextHandle();

        _ = Assert.ThrowsException<NullReferenceException>(() =>
        {
            _ = sigingContext.AsRef().ToString();
        });
    }
}
