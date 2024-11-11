// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;
using Dorssel.Security.Cryptography.InteropServices;

namespace Dorssel.Security.Cryptography;

public sealed class Xmss
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

    static unsafe void CustomZeroizeFunction(void* ptr, nuint size)
    {
        CryptographicOperations.ZeroMemory(new(ptr, (int)size));
    }

    public void GeneratePrivateKey(XmssParameterSet parameterSet, bool enableIndexObfuscation)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, typeof(Xmss));

        if (StateManager is null)
        {
            throw new InvalidOperationException("State manager not set.");
        }

        unsafe
        {
            XmssSigningContext* signingContextPtr = null;
            var result = UnsafeNativeMethods.xmss_context_initialize(ref signingContextPtr, (XmssParameterSetOID)parameterSet,
                NativeMemory.Realloc, NativeMemory.Free, CustomZeroizeFunction);
            XmssException.ThrowIfNotOkay(result);
            using var signingContext = SafeSigningContextHandle.TakeOwnership(ref signingContextPtr);

            XmssKeyContext* keyContextPtr = null;
            XmssPrivateKeyStatelessBlob* privateKeyStatelessBlobPtr = null;
            XmssPrivateKeyStatefulBlob* privateKeyStatefulBlobPtr = null;
            XmssBuffer secure_random;
            XmssBuffer random = new();
            fixed (byte* secureRandomPtr = RandomNumberGenerator.GetBytes(96))
            fixed (byte* randomPtr = RandomNumberGenerator.GetBytes(32))
            {
                secure_random.data = secureRandomPtr;
                secure_random.data_size = 96;
                random.data = randomPtr;
                random.data_size = 32;

                result = UnsafeNativeMethods.xmss_generate_private_key(ref keyContextPtr, ref privateKeyStatelessBlobPtr,
                    ref privateKeyStatefulBlobPtr, secure_random, enableIndexObfuscation
                        ? XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_ON : XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_OFF,
                    random, signingContext.AsRef());
                XmssException.ThrowIfNotOkay(result);
            }
            using var keyContext = SafeKeyContextHandle.TakeOwnership(ref keyContextPtr);
            using var privateKeyStatelessBlob = SafeNativeMemoryHandle.TakeOwnership(ref privateKeyStatelessBlobPtr);
            using var privateKeyStatefulBlob = SafeNativeMemoryHandle.TakeOwnership(ref privateKeyStatefulBlobPtr);

            var paramaterSetBytes = new byte[sizeof(int)];
            BinaryPrimitives.WriteInt32BigEndian(paramaterSetBytes, (int)parameterSet);

            StateManager.Store(XmssKeyParts.ParameterSet, paramaterSetBytes);
            StateManager.Store(XmssKeyParts.PrivateStateless, new(privateKeyStatelessBlob.AsRef().data, (int)privateKeyStatelessBlob.AsRef().data_size));
            StateManager.Store(XmssKeyParts.PrivateStateful, new(privateKeyStatefulBlob.AsRef().data, (int)privateKeyStatefulBlob.AsRef().data_size));
        }
    }

    public void LoadPrivateKey()
    {
        ObjectDisposedException.ThrowIf(IsDisposed, typeof(Xmss));

        if (StateManager is null)
        {
            throw new InvalidOperationException("State manager not set.");
        }

        unsafe
        {
            var parameterSet = (XmssParameterSetOID)BinaryPrimitives.ReadInt32BigEndian(StateManager.Load(XmssKeyParts.ParameterSet));

            XmssSigningContext* signingContextPtr = null;
            var result = UnsafeNativeMethods.xmss_context_initialize(ref signingContextPtr, parameterSet,
                NativeMemory.Realloc, NativeMemory.Free, CustomZeroizeFunction);
            XmssException.ThrowIfNotOkay(result);
            using var signingContext = SafeSigningContextHandle.TakeOwnership(ref signingContextPtr);

            XmssKeyContext* keyContextPtr = null;
            var statelessData = StateManager.Load(XmssKeyParts.PrivateStateless);
            var statefulData = StateManager.Load(XmssKeyParts.PrivateStateful);
            fixed (byte* privateKeyStatelessBlobPtr = new byte[sizeof(nuint) + statelessData.Length])
            fixed (byte* privateKeyStatefulBlobPtr = new byte[sizeof(nuint) + statefulData.Length])
            {
                *(nuint*)privateKeyStatelessBlobPtr = (nuint)statelessData.Length;
                statelessData.CopyTo(new Span<byte>(privateKeyStatelessBlobPtr + sizeof(nuint), statelessData.Length));

                *(nuint*)privateKeyStatefulBlobPtr = (nuint)statefulData.Length;
                statefulData.CopyTo(new Span<byte>(privateKeyStatefulBlobPtr + sizeof(nuint), statefulData.Length));

                result = UnsafeNativeMethods.xmss_load_private_key(ref keyContextPtr, *(XmssPrivateKeyStatelessBlob*)privateKeyStatelessBlobPtr,
                    *(XmssPrivateKeyStatefulBlob*)privateKeyStatefulBlobPtr, signingContext.AsRef());
                XmssException.ThrowIfNotOkay(result);
            }

            using var keyContext = SafeKeyContextHandle.TakeOwnership(ref keyContextPtr);
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
