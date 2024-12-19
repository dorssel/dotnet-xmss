// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dorssel.Security.Cryptography.Internal;
using Dorssel.Security.Cryptography.InteropServices;

namespace Dorssel.Security.Cryptography;

public sealed class Xmss
    : AsymmetricAlgorithm
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

    public static Version NativeHeadersVersion => new(Defines.XMSS_LIBRARY_VERSION_MAJOR, Defines.XMSS_LIBRARY_VERSION_MINOR,
                Defines.XMSS_LIBRARY_VERSION_PATCH);

    public static Version NativeLibraryVersion
    {
        get
        {
            var nativeVersion = SafeNativeMethods.xmss_library_get_version();
            return new(Defines.XMSS_LIBRARY_GET_VERSION_MAJOR(nativeVersion),
                Defines.XMSS_LIBRARY_GET_VERSION_MINOR(nativeVersion), Defines.XMSS_LIBRARY_GET_VERSION_PATCH(nativeVersion));
        }
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

    // See https://datatracker.ietf.org/doc/draft-ietf-lamps-x509-shbs/.
    // Appendix B suggests the FriendlyName is "xmss" (lowercase); the others are "extra".
    public static readonly string[] IdAlgXmssHashsigNames = ["xmss", "id-alg-xmss-hashsig", "XMSS"];

    // See https://iana.org/assignments/xmss-extended-hash-based-signatures/.
    public static readonly Oid IdAlgXmssHashsig = new("1.3.6.1.5.5.7.6.34", IdAlgXmssHashsigNames.First());

    [UnsupportedOSPlatform("browser")]
    public static void RegisterWithCryptoConfig()
    {
        lock (RegistrationLock)
        {
            if (!TriedRegisterOnce)
            {
                TriedRegisterOnce = true;
                CryptoConfig.AddAlgorithm(typeof(Xmss), IdAlgXmssHashsigNames);
                CryptoConfig.AddOID(IdAlgXmssHashsig.Value!, IdAlgXmssHashsigNames);
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

    [MemberNotNullWhen(true, nameof(PrivateKey))]
    public bool HasPrivateKey => PrivateKey is not null;

    public bool HasPublicKey { get; private set; }

    [StackTraceHidden]
    [MemberNotNull(nameof(PrivateKey))]
    void ThrowIfNoPrivateKey()
    {
        if (!HasPrivateKey)
        {
            throw new InvalidOperationException("No private key.");
        }
    }

    [StackTraceHidden]
    void ThrowIfNoPublicKey()
    {
        if (!HasPublicKey)
        {
            throw new InvalidOperationException("No public key.");
        }
    }

    [StackTraceHidden]
    static void ThrowIfUnsupportedAlgorithmOid(Oid algorithmOid)
    {
        if (algorithmOid.Value != IdAlgXmssHashsig.Value)
        {
            throw new CryptographicException($"Invalid public key algorithm OID ({algorithmOid.Value}), expected {IdAlgXmssHashsig.Value}.");
        }
    }

    public void GeneratePrivateKey(IXmssStateManager stateManager, XmssParameterSet parameterSet, bool enableIndexObfuscation)
    {
        ArgumentNullException.ThrowIfNull(stateManager);

        ObjectDisposedException.ThrowIf(IsDisposed, this);

        XmssError result;

        unsafe
        {
            using var keyContext = new CriticalXmssKeyContextHandle();
            using var signingContext = new CriticalXmssSigningContextHandle();
            {
                result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext.AsPointerRef(), (XmssParameterSetOID)parameterSet,
                    &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
                XmssException.ThrowIfNotOkay(result);
            }

            using var privateKeyStatelessBlob = new CriticalXmssPrivateKeyStatelessBlobHandle();
            using var privateKeyStatefulBlob = new CriticalXmssPrivateKeyStatefulBlobHandle();
            {
                var allRandomPtr = stackalloc byte[96 + 32];
                var allRandom = new Span<byte>(allRandomPtr, 96 + 32);

                RandomNumberGenerator.Fill(allRandom);

                XmssBuffer secure_random = new() { data = allRandomPtr, data_size = 96 };
                XmssBuffer random = new() { data = allRandomPtr + 96, data_size = 32 };

                result = UnsafeNativeMethods.xmss_generate_private_key(ref keyContext.AsPointerRef(), ref privateKeyStatelessBlob.AsPointerRef(),
                    ref privateKeyStatefulBlob.AsPointerRef(), secure_random, enableIndexObfuscation
                        ? XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_ON : XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_OFF,
                    random, signingContext.AsRef());
                XmssException.ThrowIfNotOkay(result);

                CryptographicOperations.ZeroMemory(allRandom);
            }

            stateManager.Store(XmssKeyPart.PrivateStateless, privateKeyStatelessBlob.Data);
            stateManager.Store(XmssKeyPart.PrivateStateful, privateKeyStatefulBlob.Data);

            PrivateKey?.Dispose();
            ParameterSet = parameterSet;
            PrivateKey = new(stateManager);
            PrivateKey.KeyContext.SwapWith(keyContext);
            PrivateKey.StatefulBlob.SwapWith(privateKeyStatefulBlob);
            HasPublicKey = false;
        }
    }

    public void ImportPrivateKey(IXmssStateManager stateManager)
    {
        ArgumentNullException.ThrowIfNull(stateManager);
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        XmssError result;

        unsafe
        {
            using var privateKeyStatefulBlob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();
            using var privateKeyStatelessBlob = CriticalXmssPrivateKeyStatelessBlobHandle.Alloc();
            stateManager.Load(XmssKeyPart.PrivateStateless, privateKeyStatelessBlob.Data);
            stateManager.Load(XmssKeyPart.PrivateStateful, privateKeyStatefulBlob.Data);

            foreach (var oid in Enum.GetValues<XmssParameterSetOID>())
            {
                using var keyContext = new CriticalXmssKeyContextHandle();
                using var signingContext = new CriticalXmssSigningContextHandle();
                result = UnsafeNativeMethods.xmss_context_initialize(ref signingContext.AsPointerRef(), oid,
                    &UnmanagedFunctions.Realloc, &UnmanagedFunctions.Free, &UnmanagedFunctions.Zeroize);
                XmssException.ThrowIfNotOkay(result);

                result = UnsafeNativeMethods.xmss_load_private_key(ref keyContext.AsPointerRef(),
                    privateKeyStatelessBlob.AsRef(), privateKeyStatefulBlob.AsRef(), signingContext.AsRef());
                if (result == XmssError.XMSS_OKAY)
                {
                    PrivateKey?.Dispose();
                    ParameterSet = (XmssParameterSet)oid;
                    PrivateKey = new(stateManager);
                    PrivateKey.KeyContext.SwapWith(keyContext);
                    PrivateKey.StatefulBlob.SwapWith(privateKeyStatefulBlob);
                    HasPublicKey = false;

                    // Now try to load the internal public key part, but failure is not fatal.
                    try
                    {
                        try
                        {
                            using var publicKeyInternalBlob = CriticalXmssPublicKeyInternalBlobHandle.Alloc(XmssCacheType.XMSS_CACHE_TOP, 0,
                                ParameterSet);
                            stateManager.Load(XmssKeyPart.Public, publicKeyInternalBlob.Data);
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

            // None of the OIDs worked.
            throw new XmssException(XmssError.XMSS_ERR_INVALID_BLOB);
        }
    }

    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        var signature = new byte[Defines.XMSS_SIGNATURE_SIZE(ParameterSet.AsOID())];
        var bytesWritten = Sign(data, signature);
        XmssException.ThrowFaultDetectedIf(bytesWritten != signature.Length);
        return signature;
    }

    public int Sign(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        return TrySign(data, destination, out var bytesWritten) ? bytesWritten
            : throw new ArgumentException("Destination is too short.");
    }

    public bool TrySign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ThrowIfNoPrivateKey();

        if (destination.Length < Defines.XMSS_SIGNATURE_SIZE(ParameterSet.AsOID()))
        {
            bytesWritten = 0;
            return false;
        }

        XmssError result;

        unsafe
        {
            using var privateKeyStatefulBlob = new CriticalXmssPrivateKeyStatefulBlobHandle();

            // request signature
            result = UnsafeNativeMethods.xmss_request_future_signatures(ref privateKeyStatefulBlob.AsPointerRef(), ref PrivateKey.KeyContext.AsRef(), 1);
            XmssException.ThrowIfNotOkay(result);

            // store state
            PrivateKey.StateManager.StoreStatefulPart(PrivateKey.StatefulBlob.Data, privateKeyStatefulBlob.Data);
            PrivateKey.StatefulBlob.SwapWith(privateKeyStatefulBlob);

            // sign
            using var signatureBlob = new CriticalXmssSignatureBlobHandle();
            fixed (byte* dataPtr = data)
            {
                result = UnsafeNativeMethods.xmss_sign_message(ref signatureBlob.AsPointerRef(), ref PrivateKey.KeyContext.AsRef(),
                    new() { data = dataPtr, data_size = (nuint)data.Length });
                XmssException.ThrowIfNotOkay(result);
            }
            XmssException.ThrowFaultDetectedIf(signatureBlob.AsRef().data_size > (nuint)destination.Length);
            var signature = new ReadOnlySpan<byte>(signatureBlob.AsRef().data, (int)signatureBlob.AsRef().data_size);
            signature.CopyTo(destination);
            bytesWritten = signature.Length;
            return true;
        }
    }

    public bool Verify(Stream data, ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(data);
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ThrowIfNoPublicKey();

        // 1088 is the Least Common Multiple of the block sizes for SHA-256 (64) and SHAKE256/256 (136).
        // The result (16320) is slightly less than 16 kiB (16384).
        var possiblyOversizedBuffer = ArrayPool<byte>.Shared.Rent(15 * 1088);
        try
        {
            unsafe
            {
                var buffer = possiblyOversizedBuffer.AsSpan(0, 15 * 1088);
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
                        XmssException.ThrowFaultDetectedIf(bufferPtrVerify != bufferPtr);
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
            ArrayPool<byte>.Shared.Return(possiblyOversizedBuffer);
        }
    }

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ThrowIfNoPublicKey();

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
                XmssException.ThrowFaultDetectedIf(dataPtrVerify != dataPtr);

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
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ThrowIfNoPrivateKey();

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
        using var cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Exception? taskException = null;
        while (!cancellationTokenSource.IsCancellationRequested && completed < totalTaskCount)
        {
            while (tasks.Count < Environment.ProcessorCount && index < totalTaskCount)
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

                [ExcludeFromCodeCoverage(Justification = "Not testable, unless actual faults are injected.")]
                void HandleTaskCompletion()
                {
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
                }

                HandleTaskCompletion();
                return true;
            });
            if (completed > lastReported)
            {
                reportPercentage?.Invoke(99.0 * completed / totalTaskCount);
                lastReported = completed;
            }

            [ExcludeFromCodeCoverage(Justification = "Not testable; WASM only.")]
            Task OptionalDelayTask()
            {
                // WASM is single-threaded; give the UI a chance
                return RuntimeInformation.ProcessArchitecture == Architecture.Wasm && Environment.ProcessorCount == 1
                    ? Task.Delay(TimeSpan.FromMilliseconds(1), cancellationToken)
                    : Task.CompletedTask;
            }

            await OptionalDelayTask().ConfigureAwait(false);
        }
        await Task.WhenAll(tasks).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        XmssException.ThrowFaultDetectedIf(taskException);

        using var publicKeyInternalBlob = new CriticalXmssPublicKeyInternalBlobHandle();
        unsafe
        {
            result = UnsafeNativeMethods.xmss_finish_calculate_public_key(ref publicKeyInternalBlob.AsPointerRef(),
                ref keyGenerationContext.AsPointerRef(), ref PrivateKey.KeyContext.AsRef());
            XmssException.ThrowIfNotOkay(result);
        }
        PrivateKey.StateManager.DeletePublicPart();
        PrivateKey.StateManager.Store(XmssKeyPart.Public, publicKeyInternalBlob.Data);

        result = UnsafeNativeMethods.xmss_export_public_key(out PublicKey, PrivateKey.KeyContext.AsRef());
        XmssException.ThrowIfNotOkay(result);
        HasPublicKey = true;

        reportPercentage?.Invoke(100.0);
    }

    const int AsnPublicKeyLength = 70;
    const int SubjectPublicKeyInfoLength = 85;
    const string XmssPublicKeyLabel = "XMSS PUBLIC KEY";
    const string PublicKeyLabel = "PUBLIC KEY";
    const string CertificateLabel = "CERTIFICATE";

    public byte[] ExportRfcPublicKey()
    {
        var result = new byte[Defines.XMSS_PUBLIC_KEY_SIZE];
        XmssException.ThrowFaultDetectedIf(!TryExportRfcPublicKey(result, out var bytesWritten));
        XmssException.ThrowFaultDetectedIf(bytesWritten != Defines.XMSS_PUBLIC_KEY_SIZE);
        return result;
    }

    public byte[] ExportAsnPublicKey()
    {
        var result = new byte[AsnPublicKeyLength];
        XmssException.ThrowFaultDetectedIf(!TryExportAsnPublicKey(result, out var bytesWritten));
        XmssException.ThrowFaultDetectedIf(bytesWritten != AsnPublicKeyLength);
        return result;
    }

    [Obsolete("XMSS public keys as standalone ASN.1 PEM are not standardized; consider using ExportSubjectPublicKeyInfoPem() instead.")]
    public string ExportAsnPublicKeyPem()
    {
        // Line endings may differ on different platforms; length will be somewhere beteen 2x and 3x the binary form.
        var result = new char[3 * AsnPublicKeyLength];
        XmssException.ThrowFaultDetectedIf(!TryExportAsnPublicKeyPem(result, out var charsWritten));
        return new(result[..charsWritten]);
    }

    public override byte[] ExportSubjectPublicKeyInfo()
    {
        var result = new byte[SubjectPublicKeyInfoLength];
        XmssException.ThrowFaultDetectedIf(!TryExportSubjectPublicKeyInfo(result, out var bytesWritten));
        XmssException.ThrowFaultDetectedIf(bytesWritten != SubjectPublicKeyInfoLength);
        return result;
    }

    public bool TryExportRfcPublicKey(Span<byte> destination, out int bytesWritten)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ThrowIfNoPublicKey();

        if (destination.Length < Defines.XMSS_PUBLIC_KEY_SIZE)
        {
            bytesWritten = 0;
            return false;
        }
        unsafe
        {
            fixed (XmssPublicKey* publicKeyPtr = &PublicKey)
            fixed (byte* destinationPtr = destination)
            {
                Buffer.MemoryCopy(publicKeyPtr, destinationPtr, destination.Length, Defines.XMSS_PUBLIC_KEY_SIZE);
            }
        }
        bytesWritten = Defines.XMSS_PUBLIC_KEY_SIZE;
        return true;
    }

    public bool TryExportAsnPublicKey(Span<byte> destination, out int bytesWritten)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ThrowIfNoPublicKey();

        var asnWriter = new AsnWriter(AsnEncodingRules.DER);
        {
            unsafe
            {
                fixed (XmssPublicKey* publicKeyPtr = &PublicKey)
                {
                    asnWriter.WriteOctetString(new(publicKeyPtr, sizeof(XmssPublicKey)));
                }
            }
        }
        return asnWriter.TryEncode(destination, out bytesWritten);
    }

    [Obsolete("XMSS public keys as standalone ASN.1 PEM are not standardized; consider using TryExportSubjectPublicKeyInfoPem() instead.")]
    public bool TryExportAsnPublicKeyPem(Span<char> destination, out int charsWritten)
    {
        return PemEncoding.TryWrite(XmssPublicKeyLabel, ExportAsnPublicKey(), destination, out charsWritten);
    }

    public override bool TryExportSubjectPublicKeyInfo(Span<byte> destination, out int bytesWritten)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ThrowIfNoPublicKey();

        // NOTE: new PublicKey(IdAlgXmssHashsig, new([]), new(new Span<byte>(publicKeyPtr, sizeof(XmssPublicKey))));
        // See https://github.com/dotnet/runtime/issues/110715

        var asnWriter = new AsnWriter(AsnEncodingRules.DER);
        {
            using var outer = asnWriter.PushSequence();
            {
                using var identifier = asnWriter.PushSequence();
                asnWriter.WriteObjectIdentifier(IdAlgXmssHashsig.Value!);
                // PARAMS ARE absent
            }
            unsafe
            {
                fixed (XmssPublicKey* publicKeyPtr = &PublicKey)
                {
                    asnWriter.WriteBitString(new(publicKeyPtr, sizeof(XmssPublicKey)));
                }
            }
        }
        return asnWriter.TryEncode(destination, out bytesWritten);
    }

    static void DecodeXmssPublicKey(ReadOnlySpan<byte> source, out XmssPublicKey publicKey,
        out XmssParameterSet parameterSet, out int bytesRead, bool exact)
    {
        if (source.Length < sizeof(XmssParameterSetOID))
        {
            throw new CryptographicException("Key value too short.");
        }
        var parameterSetOID = (XmssParameterSetOID)BinaryPrimitives.ReadUInt32BigEndian(source);
        if (!Enum.IsDefined(parameterSetOID))
        {
            throw new CryptographicException($"Unsupported parameter set ({parameterSetOID}).");
        }
        if (source.Length != Defines.XMSS_PUBLIC_KEY_SIZE)
        {
            throw new CryptographicException("Key value wrong size.");
        }
        unsafe
        {
            fixed (XmssPublicKey* xmssPublicKeyPtr = &publicKey)
            {
                source[..sizeof(XmssPublicKey)].CopyTo(new Span<byte>(xmssPublicKeyPtr, Defines.XMSS_PUBLIC_KEY_SIZE));
            }
        }
        bytesRead = Defines.XMSS_PUBLIC_KEY_SIZE;
        parameterSet = (XmssParameterSet)parameterSetOID;
    }

    static void DecodeAsnPublicKey(ReadOnlySpan<byte> source, out XmssPublicKey publicKey,
        out XmssParameterSet parameterSet, out int bytesRead, bool exact)
    {
        byte[] xmssPublicKeyData;
        int bytesConsumed;

        try
        {
            xmssPublicKeyData = AsnDecoder.ReadOctetString(source, AsnEncodingRules.BER, out bytesConsumed);
        }
        catch (AsnContentException ex)
        {
            throw new CryptographicException("Invalid ASN.1 format.", ex);
        }

        DecodeXmssPublicKey(xmssPublicKeyData, out publicKey, out parameterSet, out _, exact);
        bytesRead = bytesConsumed;
    }

    static void DecodeSubjectPublicKeyInfo(ReadOnlySpan<byte> source, out XmssPublicKey publicKey,
        out XmssParameterSet parameterSet, out int bytesRead, bool exact)
    {
        var x509publicKey = System.Security.Cryptography.X509Certificates.PublicKey.CreateFromSubjectPublicKeyInfo(source, out var bytesConsumed);
        if (exact && bytesConsumed < source.Length)
        {
            throw new CryptographicException("SubjectPublicKeyInfo too long.");
        }
        ThrowIfUnsupportedAlgorithmOid(x509publicKey.Oid);
        DecodeXmssPublicKey(x509publicKey.EncodedKeyValue.RawData, out publicKey, out parameterSet, out var _, true);
        bytesRead = bytesConsumed;
    }

    void ImportXmssPublicKey(XmssParameterSet parameterSet, in XmssPublicKey publicKey)
    {
        PublicKey = publicKey;
        PrivateKey?.Dispose();
        PrivateKey = null;
        ParameterSet = parameterSet;
        HasPublicKey = true;
    }

    public override void ImportFromPem(ReadOnlySpan<char> input)
    {
        PemFields? foundFields = default;
        ReadOnlySpan<char> slice = default;
        while (PemEncoding.TryFind(input, out var tmpFields))
        {
            switch (input[tmpFields.Label])
            {
                case XmssPublicKeyLabel:
                case PublicKeyLabel:
                case CertificateLabel:
                    if (foundFields is not null)
                    {
                        throw new ArgumentException("Multiple supported PEMs found.", nameof(input));
                    }
                    foundFields = tmpFields;
                    slice = input;
                    break;
            }
            input = input[tmpFields.Location.End..];
        }
        if (foundFields is null)
        {
            throw new ArgumentException("No supported PEM found.", nameof(input));
        }
        var fields = foundFields.Value;
        var possiblyOversizedData = ArrayPool<byte>.Shared.Rent(fields.DecodedDataLength);
        try
        {
            var data = possiblyOversizedData.AsSpan(0, fields.DecodedDataLength);
            XmssException.ThrowFaultDetectedIf(!Convert.TryFromBase64Chars(slice[fields.Base64Data], data, out var bytesWritten));
            XmssException.ThrowFaultDetectedIf(bytesWritten != data.Length);
            switch (slice[fields.Label])
            {
                case XmssPublicKeyLabel:
                    {
                        DecodeAsnPublicKey(data, out var publicKey, out var parameterSet, out _, true);
                        ImportXmssPublicKey(parameterSet, publicKey);
                        return;
                    }
                case PublicKeyLabel:
                    {
                        DecodeSubjectPublicKeyInfo(data, out var publicKey, out var parameterSet, out _, true);
                        ImportXmssPublicKey(parameterSet, publicKey);
                        return;
                    }
                case CertificateLabel:
                    {
                        using var certificate = new X509Certificate2(data);
                        ImportCertificatePublicKey(certificate);
                        return;
                    }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(possiblyOversizedData);
        }
    }

    public void ImportRfcPublicKey(ReadOnlySpan<byte> source, out int bytesRead)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        DecodeXmssPublicKey(source, out var publicKey, out var parameterSet, out bytesRead, false);
        ImportXmssPublicKey(parameterSet, publicKey);
    }

    public void ImportAsnPublicKey(ReadOnlySpan<byte> source, out int bytesRead)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        DecodeAsnPublicKey(source, out var publicKey, out var parameterSet, out var bytesConsumed, false);
        ImportXmssPublicKey(parameterSet, publicKey);
        bytesRead = bytesConsumed;
    }

    public override void ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source, out int bytesRead)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        DecodeSubjectPublicKeyInfo(source, out var publicKey, out var parameterSet, out var bytesConsumed, false);
        ImportXmssPublicKey(parameterSet, publicKey);
        bytesRead = bytesConsumed;
    }

    public void ImportCertificatePublicKey(PublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        ThrowIfUnsupportedAlgorithmOid(publicKey.Oid);
        DecodeXmssPublicKey(publicKey.EncodedKeyValue.RawData, out var xmssPublicKey, out var parameterSet, out var _, true);
        ImportXmssPublicKey(parameterSet, xmssPublicKey);
    }

    public void ImportCertificatePublicKey(X509Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        ThrowIfUnsupportedAlgorithmOid(new(certificate.GetKeyAlgorithm()));
        DecodeXmssPublicKey(certificate.GetPublicKey(), out var publicKey, out var parameterSet, out var _, true);
        ImportXmssPublicKey(parameterSet, publicKey);
    }

    public void ImportCertificatePublicKey(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        ImportCertificatePublicKey(certificate.PublicKey);
    }
}
