// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Buffers;
using System.Diagnostics;
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

    bool IsDisposed;
    IXmssStateManager? StateManager;
    SafeXmssKeyContextHandle? KeyContext;

    protected override void Dispose(bool disposing)
    {
        if (!IsDisposed)
        {
            KeyContext?.Dispose();
            StateManager?.Dispose();
            IsDisposed = true;
        }
        base.Dispose(disposing);
    }

    public void GeneratePrivateKey(IXmssStateManager stateManager, XmssParameterSet parameterSet, bool enableIndexObfuscation)
    {
        ArgumentNullException.ThrowIfNull(stateManager);

        ObjectDisposedException.ThrowIf(IsDisposed, typeof(Xmss));

        XmssError result;

        unsafe
        {
            using var signingContext = new SafeXmssSigningContextHandle();
            {
                result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext.AsPointerRef(), (XmssParameterSetOID)parameterSet,
                    &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
                XmssException.ThrowIfNotOkay(result);
            }

            // Private key
            using var keyContext = new SafeXmssKeyContextHandle();
            using var privateKeyStatelessBlob = new SafeXmssPrivateKeyStatelessBlobHandle();
            using var privateKeyStatefulBlob = new SafeXmssPrivateKeyStatefulBlobHandle();
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

            stateManager.Store(XmssKeyParts.PrivateStateless, privateKeyStatelessBlob.Data);
            stateManager.Store(XmssKeyParts.PrivateStateful, privateKeyStatefulBlob.Data);
            RequiresPublicKeyGeneration = true;

            StateManager = stateManager;
            KeyContext = keyContext;
        }
    }

    public bool RequiresPublicKeyGeneration { get; private set; }

    public void ImportPrivateKey(IXmssStateManager stateManager)
    {
        ArgumentNullException.ThrowIfNull(stateManager);
        ObjectDisposedException.ThrowIf(IsDisposed, typeof(Xmss));

        XmssError result;

        unsafe
        {
            using var privateKeyStatelessBlob = SafeXmssPrivateKeyStatelessBlobHandle.Alloc();
            using var privateKeyStatefulBlob = SafeXmssPrivateKeyStatefulBlobHandle.Alloc();
            stateManager.Load(XmssKeyParts.PrivateStateless, privateKeyStatelessBlob.Data);
            stateManager.Load(XmssKeyParts.PrivateStateful, privateKeyStatefulBlob.Data);

            foreach (var oid in Enum.GetValues<XmssParameterSetOID>())
            {
                using var signingContext = new SafeXmssSigningContextHandle();
                result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext.AsPointerRef(), oid,
                    &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
                XmssException.ThrowIfNotOkay(result);

                var keyContext = new SafeXmssKeyContextHandle();
                try
                {
                    result = UnsafeNativeMethods.xmss_load_private_key(ref keyContext.AsPointerRef(),
                        privateKeyStatelessBlob.AsRef(), privateKeyStatefulBlob.AsRef(), signingContext.AsRef());

                    if (result == XmssError.XMSS_OKAY)
                    {
                        StateManager?.Dispose();
                        KeyContext?.Dispose();

                        ParameterSet = (XmssParameterSet)oid;
                        KeyContext = keyContext;
                        keyContext = null;
                        StateManager = stateManager;

                        // Now try to load the internal public key part, but failure is not fatal.
                        try
                        {
                            try
                            {
                                using var publicKeyInternalBlob = SafeXmssPublicKeyInternalBlobHandle.Alloc(XmssCacheType.XMSS_CACHE_TOP, 0, ParameterSet);
                                stateManager.Load(XmssKeyParts.Public, publicKeyInternalBlob.Data);
                                // The cache will be automatically freed with the key context; we don't need it.
                                XmssInternalCache* cache = null;
                                _ = UnsafeNativeMethods.xmss_load_public_key(ref cache, ref KeyContext.AsRef(), publicKeyInternalBlob.AsRef());
                            }
                            catch (Exception ex)
                            {
                                RequiresPublicKeyGeneration = true;
                                throw new XmssException(XmssError.XMSS_ERR_INVALID_BLOB, ex);
                            }
                        }
                        catch (XmssException) { }
                        return;
                    }
                }
                finally
                {
                    keyContext?.Dispose();
                }
            }

            // None of the OIDs worked.
            throw new XmssException(XmssError.XMSS_ERR_INVALID_BLOB);
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
        if (StateManager is null || KeyContext is null)
        {
            throw new InvalidOperationException("No private key.");
        }

        if (destination.Length < Defines.XMSS_SIGNATURE_SIZE(ParameterSet.AsOID()))
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }

        XmssError result;

        unsafe
        {
            // request signature
            using var privateKeyStatefulBlob = new SafeXmssPrivateKeyStatefulBlobHandle();
            result = UnsafeNativeMethods.xmss_request_future_signatures(ref privateKeyStatefulBlob.AsPointerRef(), ref KeyContext.AsRef(), 1);
            XmssException.ThrowIfNotOkay(result);

            // store state
            StateManager.Store(XmssKeyParts.PrivateStateful, new(privateKeyStatefulBlob.AsRef().data, (int)privateKeyStatefulBlob.AsRef().data_size));

            // sign
            using var signatureBlob = new SafeXmssSignatureBlobHandle();
            fixed (byte* dataPtr = data)
            {
                result = UnsafeNativeMethods.xmss_sign_message(ref signatureBlob.AsPointerRef(), ref KeyContext.AsRef(),
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

    public async Task GeneratePublicKeyAsync(Action<double>? progress = null, CancellationToken cancellationToken = default)
    {
        if (StateManager is null || KeyContext is null)
        {
            throw new InvalidOperationException("No private key.");
        }
        if (!RequiresPublicKeyGeneration)
        {
            throw new InvalidOperationException("Public key already generated.");
        }

        XmssError result;

        using var keyGenerationContext = new SafeXmssKeyGenerationContextHandle();
        unsafe
        {
            // The caches will be automatically freed with the generation context; we don't need them.
            XmssInternalCache* cache = null;
            XmssInternalCache* generationCache = null;
            result = UnsafeNativeMethods.xmss_generate_public_key(ref keyGenerationContext.AsPointerRef(), ref cache, ref generationCache,
                KeyContext.AsRef(), XmssCacheType.XMSS_CACHE_TOP, 0, 1024);
            XmssException.ThrowIfNotOkay(result);
        }

        var tasks = new HashSet<Task>();
        var index = 0;
        var completed = 0;
        while (!cancellationToken.IsCancellationRequested && completed < 1024)
        {
            while (tasks.Count < Environment.ProcessorCount && index < 1024)
            {
                var nextTaskIndex = index;
                tasks.Add(Task.Run(() =>
                {
                    result = UnsafeNativeMethods.xmss_calculate_public_key_part(ref keyGenerationContext.AsRef(), (uint)nextTaskIndex);
                    XmssException.ThrowIfNotOkay(result);
                }, cancellationToken));
                ++index;
            }
            await Task.WhenAny([.. tasks]).ConfigureAwait(false);
            tasks.RemoveWhere((task) =>
            {
                if (!task.IsCompleted)
                {
                    return false;
                }
                ++completed;
                return true;
            });
            Debug.WriteLine(completed);
            progress?.Invoke(99.0 * completed / 1024);
        }

        using var publicKeyInternalBlob = new SafeXmssPublicKeyInternalBlobHandle();
        unsafe
        {
            result = UnsafeNativeMethods.xmss_finish_calculate_public_key(ref publicKeyInternalBlob.AsPointerRef(),
                ref keyGenerationContext.AsPointerRef(), ref KeyContext.AsRef());
            XmssException.ThrowIfNotOkay(result);
        }
        StateManager.Store(XmssKeyParts.Public, publicKeyInternalBlob.Data);
        RequiresPublicKeyGeneration = false;
        progress?.Invoke(100.0);
    }
}
