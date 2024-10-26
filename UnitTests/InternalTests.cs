// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;
using NativeHelper;

namespace UnitTests;

[TestClass]
sealed unsafe class InternalTests
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
        var version = SafeNativeMethods.xmss_library_get_version();

        Assert.AreEqual(0x00020000u, version);
    }

    [TestMethod]
    public void VerificationInitValid()
    {
        XmssPublicKey publicKey;
        var signature = new uint[625];

        var schemeIdentifier = (uint)XmssParameterSetOID.XMSS_PARAM_SHAKE256_10_256;
        publicKey.scheme_identifier = BitConverter.IsLittleEndian
            ? BinaryPrimitives.ReverseEndianness(schemeIdentifier)
            : schemeIdentifier;

        var result = ExampleManagedWrappers.VerificationInit(out var context, in publicKey, signature);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        result = ExampleManagedWrappers.VerificationUpdate(ref context, [1, 2, 3, 4, 5,]);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        result = ExampleManagedWrappers.VerificationCheck(ref context, in publicKey);
        Assert.AreEqual(XmssError.XMSS_ERR_INVALID_SIGNATURE, result);
    }

    static int AllocationCount;

    static unsafe void* CustomReallocFunction(void* ptr, nuint size)
    {
        if (ptr is not null)
        {
            Debug.WriteLine($"Realloc from: 0x{(nuint)ptr:X08}");
            AllocationCount--;
        }
        ptr = NativeMemory.Realloc(ptr, size);
        Debug.WriteLine($"Realloc to: 0x{(nuint)ptr:X08}");
        AllocationCount++;
        return ptr;
    }

    static unsafe void CustomFreeFunction(void* ptr)
    {
        if (ptr is not null)
        {
            Debug.WriteLine($"Free: 0x{(nuint)ptr:X08}");
            AllocationCount--;
        }
        NativeMemory.Free(ptr);
    }

    static unsafe void CustomZeroizeFunction(void* ptr, nuint size)
    {
        CryptographicOperations.ZeroMemory(new(ptr, (int)size));
    }

    [TestMethod]
    public void TestSignVerify()
    {
        AllocationCount = 0;

        XmssSigningContext* signingContext = null;
        var result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext, XmssParameterSetOID.XMSS_PARAM_SHA2_10_256,
            CustomReallocFunction, CustomFreeFunction, CustomZeroizeFunction);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        XmssKeyContext* keyContext = null;
        XmssPrivateKeyStatelessBlob* privateKeyStatelessBlob = null;
        XmssPrivateKeyStatefulBlob* privateKeyStatefulBlob = null;
        XmssBuffer secure_random;
        XmssBuffer random = new();
        fixed (byte* secureRandomPtr = RandomNumberGenerator.GetBytes(96))
        {
            secure_random.data = secureRandomPtr;
            secure_random.data_size = 96;
            fixed (byte* randomPtr = RandomNumberGenerator.GetBytes(32))
            {
                random.data = randomPtr;
                random.data_size = 32;

                result = UnsafeNativeMethods.xmss_generate_private_key(ref keyContext, ref privateKeyStatelessBlob, ref privateKeyStatefulBlob,
                    in secure_random, XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_ON, in random, in *signingContext);
                Assert.AreEqual(XmssError.XMSS_OKAY, result);
            }
        }

        XmssKeyGenerationContext* keyGenerationContext = null;
        XmssInternalCache* cache = null;
        XmssInternalCache* generationCache = null;
        result = UnsafeNativeMethods.xmss_generate_public_key(ref keyGenerationContext, ref cache, ref generationCache, in *keyContext,
            XmssCacheType.XMSS_CACHE_TOP, 0, 1);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        result = UnsafeNativeMethods.xmss_calculate_public_key_part(ref *keyGenerationContext, 0);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        XmssPublicKeyInternalBlob* publicKeyInternal = null;

        result = UnsafeNativeMethods.xmss_finish_calculate_public_key(ref publicKeyInternal, ref keyGenerationContext, ref *keyContext);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        result = UnsafeNativeMethods.xmss_export_public_key(out var publicKey, in *keyContext);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        XmssPrivateKeyStatefulBlob* privateKeyStatefulBlobNew = null;
        result = UnsafeNativeMethods.xmss_request_future_signatures(ref privateKeyStatefulBlobNew, ref *keyContext, 1);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        XmssSignatureBlob* signatureBlob = null;
        XmssBuffer messageBuffer = new();
        var message = new byte[] { 1, 2, 3, 4, 5 };
        fixed (byte* messagePtr = message)
        {
            messageBuffer.data = messagePtr;
            messageBuffer.data_size = (nuint)message.Length;

            result = UnsafeNativeMethods.xmss_sign_message(ref signatureBlob, ref *keyContext, in messageBuffer);
            Assert.AreEqual(XmssError.XMSS_OKAY, result);
        }

        var signature = UnsafeNativeMethods.xmss_get_signature_struct(signatureBlob);

        result = UnsafeNativeMethods.xmss_verification_init(out var verificationContext, in publicKey, in *signature, signatureBlob->data_size);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        fixed (byte* messagePtr = message)
        {
            result = UnsafeNativeMethods.xmss_verification_update(ref verificationContext, messagePtr, (nuint)message.Length, out var part_verify);
            Assert.AreEqual(XmssError.XMSS_OKAY, result);
        }

        result = UnsafeNativeMethods.xmss_verification_check(ref verificationContext, in publicKey);
        Assert.AreEqual(XmssError.XMSS_OKAY, result);

        UnsafeNativeMethods.xmss_free_signing_context(signingContext);
        signingContext = null;

        UnsafeNativeMethods.xmss_free_key_generation_context(keyGenerationContext);
        keyGenerationContext = null;

        UnsafeNativeMethods.xmss_free_key_context(keyContext);
        keyContext = null;

        CustomFreeFunction(privateKeyStatelessBlob);
        privateKeyStatelessBlob = null;
        CustomFreeFunction(privateKeyStatefulBlob);
        privateKeyStatefulBlob = null;
        CustomFreeFunction(privateKeyStatefulBlobNew);
        privateKeyStatefulBlobNew = null;
        CustomFreeFunction(publicKeyInternal);
        publicKeyInternal = null;
        CustomFreeFunction(signatureBlob);
        signatureBlob = null;
        signature = null;

        Assert.AreEqual(0, AllocationCount);
    }
}
