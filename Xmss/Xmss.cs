// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
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

    public static new Xmss Create()
    {
        return new Xmss();
    }

    [UnsupportedOSPlatform("browser")]
    [Obsolete("Cryptographic factory methods accepting an algorithm name are obsolete. Use the parameterless Create factory method on the algorithm type instead.")]
    [RequiresUnreferencedCode("The default algorithm implementations might be removed, use strong type references like 'Xmss.Create()' instead.")]
    public static new Xmss? Create(string algorithm)
    {
        ArgumentNullException.ThrowIfNull(algorithm);

        RegisterWithCryptoConfig();
        return CryptoConfig.CreateFromName(algorithm) as Xmss;
    }

    static readonly object RegistrationLock = new();
    static bool TriedRegisterOnce;

    [UnsupportedOSPlatform("browser")]
    public static void RegisterWithCryptoConfig()
    {
        lock (RegistrationLock)
        {
            if (!TriedRegisterOnce)
            {
                TriedRegisterOnce = true;
                CryptoConfig.AddAlgorithm(typeof(Xmss), "XMSS");
                CryptoConfig.AddOID("1.3.6.1.5.5.7.6.34", "XMSS");
            }
        }
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
    XmssPrivateKey? PrivateKey;
    XmssPublicKey PublicKey;

    protected override void Dispose(bool disposing)
    {
        if (!IsDisposed)
        {
            PrivateKey?.Dispose();
            PrivateKey = null;
            HasPublicKey = false;
            IsDisposed = true;
        }
        base.Dispose(disposing);
    }

    public bool HasPrivateKey => PrivateKey is not null;

    public bool HasPublicKey { get; private set; }

    public void GeneratePrivateKey(IXmssStateManager stateManager, XmssParameterSet parameterSet, bool enableIndexObfuscation)
    {
        ArgumentNullException.ThrowIfNull(stateManager);

        ObjectDisposedException.ThrowIf(IsDisposed, typeof(Xmss));

        XmssError result;

        unsafe
        {
            var keyContext = new CriticalXmssKeyContextHandle();
            var privateKeyStatefulBlob = new CriticalXmssPrivateKeyStatefulBlobHandle();
            try
            {
                using var signingContext = new CriticalXmssSigningContextHandle();
                {
                    result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext.AsPointerRef(), (XmssParameterSetOID)parameterSet,
                        &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
                    XmssException.ThrowIfNotOkay(result);
                }

                // Private key
                using var privateKeyStatelessBlob = new CriticalXmssPrivateKeyStatelessBlobHandle();
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

                stateManager.Store(XmssKeyParts.PrivateStateless, [], privateKeyStatelessBlob.Data);
                stateManager.Store(XmssKeyParts.PrivateStateful, [], privateKeyStatefulBlob.Data);

                PrivateKey?.Dispose();
                ParameterSet = parameterSet;
                PrivateKey = new(stateManager, keyContext, privateKeyStatefulBlob);
                keyContext = null;
                privateKeyStatefulBlob = null;
                HasPublicKey = false;
            }
            finally
            {
                keyContext?.Dispose();
                privateKeyStatefulBlob?.Dispose();
            }
        }
    }

    public void ImportPrivateKey(IXmssStateManager stateManager)
    {
        ArgumentNullException.ThrowIfNull(stateManager);
        ObjectDisposedException.ThrowIf(IsDisposed, typeof(Xmss));

        XmssError result;

        unsafe
        {
            var privateKeyStatefulBlob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();
            try
            {
                using var privateKeyStatelessBlob = CriticalXmssPrivateKeyStatelessBlobHandle.Alloc();
                stateManager.Load(XmssKeyParts.PrivateStateless, privateKeyStatelessBlob.Data);
                stateManager.Load(XmssKeyParts.PrivateStateful, privateKeyStatefulBlob.Data);

                foreach (var oid in Enum.GetValues<XmssParameterSetOID>())
                {
                    CriticalXmssKeyContextHandle? keyContext = new();
                    try
                    {
                        using var signingContext = new CriticalXmssSigningContextHandle();
                        result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext.AsPointerRef(), oid,
                            &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
                        XmssException.ThrowIfNotOkay(result);

                        result = UnsafeNativeMethods.xmss_load_private_key(ref keyContext.AsPointerRef(),
                            privateKeyStatelessBlob.AsRef(), privateKeyStatefulBlob.AsRef(), signingContext.AsRef());
                        signingContext.Dispose();

                        if (result == XmssError.XMSS_OKAY)
                        {
                            PrivateKey?.Dispose();
                            ParameterSet = (XmssParameterSet)oid;
                            PrivateKey = new(stateManager, keyContext, privateKeyStatefulBlob);
                            keyContext = null;
                            privateKeyStatefulBlob = null;
                            HasPublicKey = false;

                            // Now try to load the internal public key part, but failure is not fatal.
                            try
                            {
                                try
                                {
                                    using var publicKeyInternalBlob = CriticalXmssPublicKeyInternalBlobHandle.Alloc(XmssCacheType.XMSS_CACHE_TOP, 0,
                                        ParameterSet);
                                    stateManager.Load(XmssKeyParts.Public, publicKeyInternalBlob.Data);
                                    // The cache will be automatically freed with the key context; we don't need it.
                                    XmssInternalCache* cache = null;
                                    result = UnsafeNativeMethods.xmss_load_public_key(ref cache, ref PrivateKey.KeyContext.AsRef(),
                                        publicKeyInternalBlob.AsRef());
                                    XmssException.ThrowIfNotOkay(result);

                                    result = UnsafeNativeMethods.xmss_export_public_key(out PublicKey, PrivateKey.KeyContext.AsRef());
                                    XmssException.ThrowIfNotOkay(result);
                                    HasPublicKey = true;
                                }
                                catch (Exception ex) when (ex is not XmssException)
                                {
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
            finally
            {
                privateKeyStatefulBlob?.Dispose();
            }
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
        if (PrivateKey is null)
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
            var privateKeyStatefulBlob = new CriticalXmssPrivateKeyStatefulBlobHandle();
            try
            {
                // request signature
                result = UnsafeNativeMethods.xmss_request_future_signatures(ref privateKeyStatefulBlob.AsPointerRef(), ref PrivateKey.KeyContext.AsRef(), 1);
                XmssException.ThrowIfNotOkay(result);

                // store state
                PrivateKey.StateManager.Store(XmssKeyParts.PrivateStateful, PrivateKey.StatefulBlob.Data, privateKeyStatefulBlob.Data);
                PrivateKey.StatefulBlob = privateKeyStatefulBlob;
                privateKeyStatefulBlob = null;

                // sign
                using var signatureBlob = new CriticalXmssSignatureBlobHandle();
                fixed (byte* dataPtr = data)
                {
                    result = UnsafeNativeMethods.xmss_sign_message(ref signatureBlob.AsPointerRef(), ref PrivateKey.KeyContext.AsRef(),
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
            finally
            {
#pragma warning disable CA1508 // Avoid dead conditional code
                privateKeyStatefulBlob?.Dispose();
#pragma warning restore CA1508 // Avoid dead conditional code
            }
        }
    }

    public bool Verify(Stream data, ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (!HasPublicKey)
        {
            throw new InvalidOperationException("No public key.");
        }

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

    public async Task GeneratePublicKeyAsync(Action<double>? reportPercentage = null, CancellationToken cancellationToken = default)
    {
        if (PrivateKey is null)
        {
            throw new InvalidOperationException("No private key.");
        }
        if (HasPublicKey)
        {
            throw new InvalidOperationException("Public key already generated.");
        }

        XmssError result;

        using var keyGenerationContext = new CriticalXmssKeyGenerationContextHandle();
        var totalTaskCount = 1 << Defines.XMSS_TREE_DEPTH(ParameterSet.AsOID());
        unsafe
        {
            // The caches will be automatically freed with the generation context; we don't need them.
            XmssInternalCache* cache = null;
            XmssInternalCache* generationCache = null;
            result = UnsafeNativeMethods.xmss_generate_public_key(ref keyGenerationContext.AsPointerRef(), ref cache, ref generationCache,
                PrivateKey.KeyContext.AsRef(), XmssCacheType.XMSS_CACHE_TOP, 0, (uint)totalTaskCount);
            XmssException.ThrowIfNotOkay(result);
        }

        var tasks = new HashSet<Task>();
        var index = 0;
        var completed = 0;
        var lastReported = 0;
        var concurrentTaskCount = RuntimeInformation.ProcessArchitecture == Architecture.Wasm ? 1 : Environment.ProcessorCount;
        using var cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Exception? taskException = null;
        while (!cancellationTokenSource.IsCancellationRequested && completed < totalTaskCount)
        {
            while (tasks.Count < concurrentTaskCount && index < totalTaskCount)
            {
                var nextTaskIndex = index;
                _ = tasks.Add(Task.Run(() =>
                {
                    result = UnsafeNativeMethods.xmss_calculate_public_key_part(ref keyGenerationContext.AsRef(), (uint)nextTaskIndex);
                    XmssException.ThrowIfNotOkay(result);
                }, cancellationTokenSource.Token));
                ++index;
            }
            _ = await Task.WhenAny([.. tasks]).ConfigureAwait(false);
            _ = tasks.RemoveWhere((task) =>
            {
                if (!task.IsCompleted)
                {
                    // not done yet
                    return false;
                }
                if (task.Exception is null)
                {
                    // success
                    ++completed;
                }
                else
                {
                    // failed, remember the first failure and cancel others
                    taskException ??= task.Exception;
                    cancellationTokenSource.Cancel();
                }
                return true;
            });
            if (completed > lastReported)
            {
                reportPercentage?.Invoke(99.0 * completed / totalTaskCount);
                lastReported = completed;
            }
            if (RuntimeInformation.ProcessArchitecture == Architecture.Wasm)
            {
                // WASM is (still) single-threaded; give the UI a chance
                await Task.Delay(TimeSpan.FromMilliseconds(1), cancellationToken).ConfigureAwait(false);
            }
        }
        await Task.WhenAll(tasks).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (taskException is not null)
        {
            throw taskException;
        }

        using var publicKeyInternalBlob = new CriticalXmssPublicKeyInternalBlobHandle();
        unsafe
        {
            result = UnsafeNativeMethods.xmss_finish_calculate_public_key(ref publicKeyInternalBlob.AsPointerRef(),
                ref keyGenerationContext.AsPointerRef(), ref PrivateKey.KeyContext.AsRef());
            XmssException.ThrowIfNotOkay(result);
        }
        PrivateKey.StateManager.DeletePublicPart();
        PrivateKey.StateManager.Store(XmssKeyParts.Public, [], publicKeyInternalBlob.Data);

        result = UnsafeNativeMethods.xmss_export_public_key(out PublicKey, PrivateKey.KeyContext.AsRef());
        XmssException.ThrowIfNotOkay(result);
        HasPublicKey = true;

        reportPercentage?.Invoke(100.0);
    }
}
