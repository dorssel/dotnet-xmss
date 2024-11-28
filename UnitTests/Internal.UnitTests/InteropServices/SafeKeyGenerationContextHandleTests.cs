// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using Dorssel.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;
using Dorssel.Security.Cryptography.InteropServices;

namespace Internal.UnitTests.InteropServices;

[TestClass]
sealed unsafe class SafeKeyGenerationContextHandleTests
{
    static unsafe XmssKeyGenerationContext* CreateKeyGenerationContextPointer(ref XmssKeyContext* keyContext)
    {
        XmssSigningContext* signingContext = null;
        var result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext, XmssParameterSetOID.XMSS_PARAM_SHA2_10_256,
            &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        XmssPrivateKeyStatelessBlob* privateKeyStatelessBlob = null;
        XmssPrivateKeyStatefulBlob* privateKeyStatefulBlob = null;
        var secureRandomData = stackalloc byte[96];
        XmssBuffer secure_random = new() { data_size = 96, data = secureRandomData };
        var randomData = stackalloc byte[32];
        XmssBuffer random = new() { data_size = 32, data = randomData };
        result = UnsafeNativeMethods.xmss_generate_private_key(ref keyContext, ref privateKeyStatelessBlob, ref privateKeyStatefulBlob,
            in secure_random, XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_OFF, in random, in *signingContext);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        XmssKeyGenerationContext* keyGenerationContext = null;
        XmssInternalCache* cache = null;
        XmssInternalCache* generationCache = null;
        result = UnsafeNativeMethods.xmss_generate_public_key(ref keyGenerationContext, ref cache, ref generationCache,
            *keyContext, XmssCacheType.XMSS_CACHE_TOP, 0, 1);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        // free everything else
        UnsafeNativeMethods.xmss_free_signing_context(signingContext);
        signingContext = null;
        NativeMemory.Free(privateKeyStatelessBlob);
        privateKeyStatelessBlob = null;
        NativeMemory.Free(privateKeyStatefulBlob);
        privateKeyStatefulBlob = null;

        return keyGenerationContext;
    }

    [TestMethod]
    public void AsRef_Valid()
    {
        // We need to keep the XmssKeyContext alive while handling the XmssKeyGenerationContext.
        using var keyContext = new SafeKeyContextHandle();

        using var keyGenerationContext = new SafeKeyGenerationContextHandle();
        keyGenerationContext.AsPointerRef() = CreateKeyGenerationContextPointer(ref keyContext.AsPointerRef());

        _ = keyGenerationContext.AsRef().ToString();
    }

    [TestMethod]
    public void AsRef_Null()
    {
        using var keyGenerationContext = new SafeKeyGenerationContextHandle();

        _ = Assert.ThrowsException<NullReferenceException>(() =>
        {
            _ = keyGenerationContext.AsRef().ToString();
        });
    }
}
