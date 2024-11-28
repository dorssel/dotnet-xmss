﻿// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Buffers;
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
        LegalKeySizesValue = [new(256, 256, 0)];
        KeySizeValue = 256;
    }

    public XmssParameterSet ParameterSet { get; private set; } = XmssParameterSet.None;

    public override string? SignatureAlgorithm => ParameterSet switch
    {
        // See https://www.iana.org/assignments/xml-security-uris/xml-security-uris.xhtml
        // and https://www.rfc-editor.org/rfc/rfc9231.html#name-xmss-and-xmssmt

        XmssParameterSet.XMSS_SHA2_10_256 => "http://www.w3.org/2021/04/xmldsig-more#xmss-sha2-10-256",
        XmssParameterSet.XMSS_SHA2_16_256 => "http://www.w3.org/2021/04/xmldsig-more#xmss-sha2-16-256",
        XmssParameterSet.XMSS_SHA2_20_256 => "http://www.w3.org/2021/04/xmldsig-more#xmss-sha2-20-256",
        XmssParameterSet.XMSS_SHAKE256_10_256 => "http://www.w3.org/2021/04/xmldsig-more#xmss-shake256-10-256",
        XmssParameterSet.XMSS_SHAKE256_16_256 => "http://www.w3.org/2021/04/xmldsig-more#xmss-shake256-16-256",
        XmssParameterSet.XMSS_SHAKE256_20_256 => "http://www.w3.org/2021/04/xmldsig-more#xmss-shake256-20-256",
        XmssParameterSet.None or _ => throw new InvalidOperationException(),
    };

    public Xmss(IXmssStateManager stateManager)
        : this()
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

    readonly IXmssStateManager? StateManager;

    public void GeneratePrivateKey(XmssParameterSet parameterSet, bool enableIndexObfuscation)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, typeof(Xmss));

        if (StateManager is null)
        {
            throw new InvalidOperationException("State manager not set.");
        }

        XmssError result;

        unsafe
        {
            using var signingContext = new SafeSigningContextHandle();
            {
                result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext.AsPointerRef(), (XmssParameterSetOID)parameterSet,
                    &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
                XmssException.ThrowIfNotOkay(result);
            }

            // Private key
            using var keyContext = new SafeKeyContextHandle();
            using var privateKeyStatelessBlob = new SafeNativeMemoryHandle<XmssPrivateKeyStatelessBlob>();
            using var privateKeyStatefulBlob = new SafeNativeMemoryHandle<XmssPrivateKeyStatefulBlob>();
            {
                XmssBuffer secure_random;
                XmssBuffer random = new();
                fixed (byte* secureRandomPtr = RandomNumberGenerator.GetBytes(96))
                fixed (byte* randomPtr = RandomNumberGenerator.GetBytes(32))
                {
                    secure_random.data = secureRandomPtr;
                    secure_random.data_size = 96;
                    random.data = randomPtr;
                    random.data_size = 32;

                    result = UnsafeNativeMethods.xmss_generate_private_key(ref keyContext.AsPointerRef(), ref privateKeyStatelessBlob.AsPointerRef(),
                        ref privateKeyStatefulBlob.AsPointerRef(), secure_random, enableIndexObfuscation
                            ? XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_ON : XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_OFF,
                        random, signingContext.AsRef());
                    XmssException.ThrowIfNotOkay(result);
                }
            }

            // Public key
            using var publicKeyInternalBlob = new SafeNativeMemoryHandle<XmssPublicKeyInternalBlob>();
            {
                using var keyGenerationContext = new SafeKeyGenerationContextHandle();
                {
                    // The caches will be automatically freed with the generation context; we don't need them.
                    XmssInternalCache* cache = null;
                    XmssInternalCache* generationCache = null;
                    result = UnsafeNativeMethods.xmss_generate_public_key(ref keyGenerationContext.AsPointerRef(), ref cache, ref generationCache,
                        keyContext.AsRef(), XmssCacheType.XMSS_CACHE_TOP, 0, 1);
                    XmssException.ThrowIfNotOkay(result);
                }

                result = UnsafeNativeMethods.xmss_calculate_public_key_part(ref keyGenerationContext.AsRef(), 0);
                XmssException.ThrowIfNotOkay(result);

                result = UnsafeNativeMethods.xmss_finish_calculate_public_key(ref publicKeyInternalBlob.AsPointerRef(),
                    ref keyGenerationContext.AsPointerRef(), ref keyContext.AsRef());
                XmssException.ThrowIfNotOkay(result);
            }

            StateManager.Store(XmssKeyParts.ParameterSet, parameterSet.ToBigEndian());
            StateManager.Store(XmssKeyParts.PrivateStateless, new(privateKeyStatelessBlob.AsRef().data, (int)privateKeyStatelessBlob.AsRef().data_size));
            StateManager.Store(XmssKeyParts.PrivateStateful, new(privateKeyStatefulBlob.AsRef().data, (int)privateKeyStatefulBlob.AsRef().data_size));
            StateManager.Store(XmssKeyParts.Public, new(publicKeyInternalBlob.AsRef().data, (int)publicKeyInternalBlob.AsRef().data_size));
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
            var parameterSet = XmssParameterSet.None;
            parameterSet.FromBigEndian(StateManager.Load(XmssKeyParts.ParameterSet));

            using var signingContext = new SafeSigningContextHandle();
            var result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext.AsPointerRef(), parameterSet.AsOID(),
                &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
            XmssException.ThrowIfNotOkay(result);

            using var keyContext = new SafeKeyContextHandle();
            var statelessData = StateManager.Load(XmssKeyParts.PrivateStateless);
            var statefulData = StateManager.Load(XmssKeyParts.PrivateStateful);
            fixed (byte* privateKeyStatelessBlobPtr = new byte[sizeof(nuint) + statelessData.Length])
            fixed (byte* privateKeyStatefulBlobPtr = new byte[sizeof(nuint) + statefulData.Length])
            {
                *(nuint*)privateKeyStatelessBlobPtr = (nuint)statelessData.Length;
                statelessData.CopyTo(new Span<byte>(privateKeyStatelessBlobPtr + sizeof(nuint), statelessData.Length));

                *(nuint*)privateKeyStatefulBlobPtr = (nuint)statefulData.Length;
                statefulData.CopyTo(new Span<byte>(privateKeyStatefulBlobPtr + sizeof(nuint), statefulData.Length));

                result = UnsafeNativeMethods.xmss_load_private_key(ref keyContext.AsPointerRef(),
                    *(XmssPrivateKeyStatelessBlob*)privateKeyStatelessBlobPtr,
                    *(XmssPrivateKeyStatefulBlob*)privateKeyStatefulBlobPtr, signingContext.AsRef());
                XmssException.ThrowIfNotOkay(result);
            }

            ParameterSet = parameterSet;
        }
    }

    public Version NativeHeadersVersion => new(Defines.XMSS_LIBRARY_VERSION_MAJOR, Defines.XMSS_LIBRARY_VERSION_MINOR,
                Defines.XMSS_LIBRARY_VERSION_PATCH);

    public Version NativeLibraryVersion
    {
        get
        {
            var nativeVersion = SafeNativeMethods.xmss_library_get_version();
            return new(Defines.XMSS_LIBRARY_GET_VERSION_MAJOR(nativeVersion),
                Defines.XMSS_LIBRARY_GET_VERSION_MINOR(nativeVersion), Defines.XMSS_LIBRARY_GET_VERSION_PATCH(nativeVersion));
        }
    }

    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        var signature = new byte[Defines.XMSS_SIGNATURE_SIZE(ParameterSet.AsOID())];
        var bytesWritten = Sign(data, signature);
        return bytesWritten == signature.Length ? signature
            : throw new XmssException(XmssError.XMSS_ERR_FAULT_DETECTED);
    }

    public int Sign(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        return TrySign(data, destination, out var bytesWritten) ? bytesWritten
            : throw new XmssException(XmssError.XMSS_ERR_FAULT_DETECTED);
    }

    public bool TrySign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
    {
        if (StateManager is null)
        {
            throw new InvalidOperationException("State manager not set.");
        }

        if (destination.Length < Defines.XMSS_SIGNATURE_SIZE(ParameterSet.AsOID()))
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }

        XmssError result;

        unsafe
        {
            using var keyContext = new SafeKeyContextHandle();
            {
                // private key
                using var signingContext = new SafeSigningContextHandle();
                {
                    result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext.AsPointerRef(), ParameterSet.AsOID(),
                        &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
                    XmssException.ThrowIfNotOkay(result);
                }

                var statelessData = StateManager.Load(XmssKeyParts.PrivateStateless);
                var statefulData = StateManager.Load(XmssKeyParts.PrivateStateful);
                fixed (byte* privateKeyStatelessBlobPtr = new byte[sizeof(nuint) + statelessData.Length])
                fixed (byte* privateKeyStatefulBlobPtr = new byte[sizeof(nuint) + statefulData.Length])
                {
                    *(nuint*)privateKeyStatelessBlobPtr = (nuint)statelessData.Length;
                    statelessData.CopyTo(new Span<byte>(privateKeyStatelessBlobPtr + sizeof(nuint), statelessData.Length));

                    *(nuint*)privateKeyStatefulBlobPtr = (nuint)statefulData.Length;
                    statefulData.CopyTo(new Span<byte>(privateKeyStatefulBlobPtr + sizeof(nuint), statefulData.Length));

                    result = UnsafeNativeMethods.xmss_load_private_key(ref keyContext.AsPointerRef(),
                        *(XmssPrivateKeyStatelessBlob*)privateKeyStatelessBlobPtr,
                        *(XmssPrivateKeyStatefulBlob*)privateKeyStatefulBlobPtr, signingContext.AsRef());
                    XmssException.ThrowIfNotOkay(result);
                }
            }

            {
                // public key
                var publicData = StateManager.Load(XmssKeyParts.Public);
                fixed (byte* publicKeyInternalBlobPtr = new byte[sizeof(nuint) + publicData.Length])
                {
                    *(nuint*)publicKeyInternalBlobPtr = (nuint)publicData.Length;
                    publicData.CopyTo(new Span<byte>(publicKeyInternalBlobPtr + sizeof(nuint), publicData.Length));

                    // The cache will be automatically freed with the key context; we don't need it.
                    XmssInternalCache* cache = null;
                    result = UnsafeNativeMethods.xmss_load_public_key(ref cache, ref keyContext.AsRef(),
                        *(XmssPublicKeyInternalBlob*)publicKeyInternalBlobPtr);
                    XmssException.ThrowIfNotOkay(result);
                }
            }

            {
                // request signature
                using var privateKeyStatefulBlob = new SafeNativeMemoryHandle<XmssPrivateKeyStatefulBlob>();
                result = UnsafeNativeMethods.xmss_request_future_signatures(ref privateKeyStatefulBlob.AsPointerRef(), ref keyContext.AsRef(), 1);
                XmssException.ThrowIfNotOkay(result);

                // store state
                StateManager.Store(XmssKeyParts.PrivateStateful, new(privateKeyStatefulBlob.AsRef().data, (int)privateKeyStatefulBlob.AsRef().data_size));

                // sign
                using var signatureBlob = new SafeNativeMemoryHandle<XmssSignatureBlob>();
                fixed (byte* dataPtr = data)
                {
                    result = UnsafeNativeMethods.xmss_sign_message(ref signatureBlob.AsPointerRef(), ref keyContext.AsRef(),
                        new() { data = dataPtr, data_size = (nuint)data.Length });
                    XmssException.ThrowIfNotOkay(result);
                }
                if (signatureBlob.AsRef().data_size > (nuint)destination.Length)
                {
                    throw new XmssException(XmssError.XMSS_ERR_FAULT_DETECTED);
                }
                var signature = new ReadOnlySpan<byte>(signatureBlob.AsRef().data, (int)signatureBlob.AsRef().data_size);
                signature.CopyTo(destination);
                bytesWritten = signature.Length;
                return true;
            }
        }
    }

    XmssPublicKey PublicKey;

    public bool Verify(Stream data, ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(data);

        // 1088 is the Least Common Multiple of the block sizes for SHA-256 (64) and SHAKE256/256 (136).
        // The result (16320) is slightly less than 16 kiB (16384).
        var buffer = ArrayPool<byte>.Shared.Rent(15 * 1088);
        try
        {
            unsafe
            {
                fixed (byte* signaturePtr = signature)
                fixed (byte* bufferPtr = buffer)
                fixed (XmssPublicKey* publicKeyPtr = &PublicKey)
                {
                    var result = UnsafeNativeMethods.xmss_verification_init(out var context, PublicKey, *(XmssSignature*)signaturePtr, (nuint)signature.Length);
                    if (result == XmssError.XMSS_ERR_INVALID_SIGNATURE)
                    {
                        return false;
                    }
                    XmssException.ThrowIfNotOkay(result);

                    int bytesRead;
                    while ((bytesRead = data.Read(new(bufferPtr, buffer.Length))) != 0)
                    {
                        result = UnsafeNativeMethods.xmss_verification_update(ref context, bufferPtr, (nuint)bytesRead, out var bufferPtrVerify);
                        XmssException.ThrowIfNotOkay(result);
                        if (bufferPtrVerify != bufferPtr)
                        {
                            throw new XmssException(XmssError.XMSS_ERR_FAULT_DETECTED);
                        }
                    }

                    result = UnsafeNativeMethods.xmss_verification_check(ref context, PublicKey);
                    if (result == XmssError.XMSS_ERR_INVALID_SIGNATURE)
                    {
                        return false;
                    }
                    XmssException.ThrowIfNotOkay(result);
                    return true;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        unsafe
        {
            fixed (byte* signaturePtr = signature)
            fixed (byte* dataPtr = data)
            fixed (XmssPublicKey* publicKeyPtr = &PublicKey)
            {
                var result = UnsafeNativeMethods.xmss_verification_init(out var context, PublicKey, *(XmssSignature*)signaturePtr, (nuint)signature.Length);
                if (result == XmssError.XMSS_ERR_INVALID_SIGNATURE)
                {
                    return false;
                }
                XmssException.ThrowIfNotOkay(result);

                result = UnsafeNativeMethods.xmss_verification_update(ref context, dataPtr, (nuint)data.Length, out var dataPtrVerify);
                XmssException.ThrowIfNotOkay(result);
                if (dataPtrVerify != dataPtr)
                {
                    throw new XmssException(XmssError.XMSS_ERR_FAULT_DETECTED);
                }

                result = UnsafeNativeMethods.xmss_verification_check(ref context, PublicKey);
                if (result == XmssError.XMSS_ERR_INVALID_SIGNATURE)
                {
                    return false;
                }
                XmssException.ThrowIfNotOkay(result);
                return true;
            }
        }
    }
}
