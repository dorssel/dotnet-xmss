// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Buffers;
using System.Buffers.Binary;
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

#pragma warning disable CA1822 // Mark members as static
    XmssParameterSet ParameterSet => XmssParameterSet.XMSS_SHA2_10_256;
#pragma warning restore CA1822 // Mark members as static

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

        unsafe
        {
            XmssSigningContext* signingContextPtr = null;
            var result = UnsafeNativeMethods.xmss_context_initialize(ref signingContextPtr, (XmssParameterSetOID)parameterSet,
                &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
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
                &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
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

    XmssPublicKey PublicKey;

    public bool Verify(Stream data, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);

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
}
