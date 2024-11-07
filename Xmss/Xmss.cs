// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography;

public class Xmss
    : AsymmetricAlgorithm
    , IXmss
{
    public Xmss()
    {
    }

    public Xmss(IXmssStateManager stateManager)
    {
        StateManager = stateManager;
    }

    bool IsDisposed;

    protected override void Dispose(bool disposing)
    {
        if (IsDisposed)
        {
            return;
        }

        if (disposing)
        {
            // ...
        }

        IsDisposed = true;

        base.Dispose(disposing);
    }

    IXmssStateManager? StateManager;

    static unsafe void* CustomReallocFunction(void* ptr, nuint size) => ptr;

    static unsafe void CustomFreeFunction(void* ptr) { }

    static unsafe void CustomZeroizeFunction(void* ptr, nuint size)
    {
        CryptographicOperations.ZeroMemory(new(ptr, (int)size));
    }

    public void GeneratePrivateKey(XmssParameterSet parameterSet)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, typeof(Xmss));

        if (StateManager is null)
        {
            throw new InvalidOperationException("State manager not set.");
        }

        unsafe
        {
            using SafeSigningContext signingContext = new();
            XmssSigningContext* signingContextPtr = signingContext;
            var result = UnsafeNativeMethods.xmss_context_initialize(ref signingContextPtr, (XmssParameterSetOID)parameterSet,
                CustomReallocFunction, CustomFreeFunction, CustomZeroizeFunction);
#if false
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
#endif
        }
    }

    public Version NativeHeadersVersion
    {
        get
        {
            return new(Defines.XMSS_LIBRARY_VERSION_MAJOR, Defines.XMSS_LIBRARY_VERSION_MINOR,
                Defines.XMSS_LIBRARY_VERSION_PATCH);
        }
    }

    public Version NativeLibraryVersion
    {
        get
        {
            var nativeVersion = SafeNativeMethods.xmss_library_get_version();
            return new(Defines.XMSS_LIBRARY_GET_VERSION_MAJOR(nativeVersion),
                Defines.XMSS_LIBRARY_GET_VERSION_MINOR(nativeVersion), Defines.XMSS_LIBRARY_GET_VERSION_PATCH(nativeVersion));
        }
    }

    public bool Verify(Stream data, byte[] signature)
    {
        throw new NotImplementedException();
    }
}
