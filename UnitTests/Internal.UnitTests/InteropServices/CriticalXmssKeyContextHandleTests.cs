﻿// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using Dorssel.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;
using Dorssel.Security.Cryptography.InteropServices;

namespace Internal.UnitTests.InteropServices;

[TestClass]
sealed unsafe class CriticalXmssKeyContextHandleTests
{
    static XmssKeyContext* CreateKeyContextPointer()
    {
        XmssSigningContext* signingContext = null;
        var result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext, XmssParameterSetOID.XMSS_PARAM_SHA2_10_256,
            &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        XmssKeyContext* keyContext = null;
        XmssPrivateKeyStatelessBlob* privateKeyStatelessBlob = null;
        XmssPrivateKeyStatefulBlob* privateKeyStatefulBlob = null;
        var secureRandomData = stackalloc byte[96];
        XmssBuffer secure_random = new() { data_size = 96, data = secureRandomData };
        var randomData = stackalloc byte[32];
        XmssBuffer random = new() { data_size = 32, data = randomData };
        result = UnsafeNativeMethods.xmss_generate_private_key(ref keyContext, ref privateKeyStatelessBlob, ref privateKeyStatefulBlob,
            in secure_random, XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_OFF, in random, in *signingContext);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        // free everything else
        UnsafeNativeMethods.xmss_free_signing_context(signingContext);
        signingContext = null;
        NativeMemory.Free(privateKeyStatelessBlob);
        privateKeyStatelessBlob = null;
        NativeMemory.Free(privateKeyStatefulBlob);
        privateKeyStatefulBlob = null;

        return keyContext;
    }

    [TestMethod]
    public void Free()
    {
        using var keyContext = new CriticalXmssKeyContextHandle();
    }
}
