// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dorssel.Security.Cryptography.Internal;
using Dorssel.Security.Cryptography.InteropServices;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// TODO
/// </summary>
public sealed class Xmss
    : AsymmetricAlgorithm
{
    #region Construction
    /// <summary>
    /// TODO
    /// </summary>
    public Xmss()
    {
        LegalKeySizesValue = [new(256, 256, 0)];
        KeySizeValue = 256;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <returns>TODO</returns>
    public static new Xmss Create()
    {
        return new Xmss();
    }
    #endregion

    #region Version
    /// <summary>
    /// TODO
    /// </summary>
    public static Version NativeHeadersVersion => new(Defines.XMSS_LIBRARY_VERSION_MAJOR, Defines.XMSS_LIBRARY_VERSION_MINOR,
                Defines.XMSS_LIBRARY_VERSION_PATCH);

    /// <summary>
    /// TODO
    /// </summary>
    public static Version NativeLibraryVersion
    {
        get
        {
            var nativeVersion = SafeNativeMethods.xmss_library_get_version();
            return new(Defines.XMSS_LIBRARY_GET_VERSION_MAJOR(nativeVersion),
                Defines.XMSS_LIBRARY_GET_VERSION_MINOR(nativeVersion), Defines.XMSS_LIBRARY_GET_VERSION_PATCH(nativeVersion));
        }
    }
    #endregion

    #region CryptoConfig
    /// <summary>
    /// XMSS Algorithm Identifier (OID) id-alg-xmss-hashsig, as registered by IANA.
    /// </summary>
    /// <remarks>
    /// The friendly name "xmss" is suggested by the certificate example of
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-lamps-x509-shbs-13.html#name-xmss-x509-v3-certificate-ex" />.
    /// </remarks>
    /// <seealso href="https://www.iana.org/assignments/smi-numbers/smi-numbers.xml#smi-numbers-1.3.6.1.5.5.7.6" />
    /// <seealso href="https://www.ietf.org/archive/id/draft-ietf-lamps-x509-shbs-13.html#name-xmss-algorithm-identifier" />
    public static Oid IdAlgXmssHashsig { get; }  = new("1.3.6.1.5.5.7.6.34", "xmss");

    static void RegisterWithCryptoConfig()
    {
        CryptoConfig.AddAlgorithm(typeof(Xmss), IdAlgXmssHashsig.FriendlyName!);
        CryptoConfig.AddOID(IdAlgXmssHashsig.Value!, IdAlgXmssHashsig.FriendlyName!);
    }

    [ExcludeFromCodeCoverage(Justification = "Not testable; WASM only.")]
    static Xmss()
    {
        try
        {
            RegisterWithCryptoConfig();
        }
        catch (PlatformNotSupportedException)
        {
            // CryptoConfig is unsupported for WASM.
        }
    }
    #endregion

    #region State
    /// <summary>
    /// TODO
    /// </summary>
    public XmssParameterSet ParameterSet { get; private set; } = XmssParameterSet.None;

    bool IsDisposed;
    XmssPrivateKey? PrivateKey;
    XmssPublicKey PublicKey;

    void ResetState()
    {
        PrivateKey?.Dispose();
        PrivateKey = null;
        HasPublicKey = false;
        ParameterSet = XmssParameterSet.None;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="disposing">TODO</param>
    protected override void Dispose(bool disposing)
    {
        if (!IsDisposed)
        {
            ResetState();
            IsDisposed = true;
        }
        base.Dispose(disposing);
    }

    /// <summary>
    /// TODO
    /// </summary>
    [MemberNotNullWhen(true, nameof(PrivateKey))]
    public bool HasPrivateKey => PrivateKey is not null;

    /// <summary>
    /// TODO
    /// </summary>
    public bool HasPublicKey { get; private set; }

    /// <summary>
    /// TODO
    /// </summary>
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
    #endregion

    #region Private Key
    static void VerifyNoPrivateState(StateManagerWrapper wrappedStateManager)
    {
        var partExists = false;

        using var statelessBlob = CriticalXmssPrivateKeyStatelessBlobHandle.Alloc();
        try
        {
            wrappedStateManager.Load(XmssKeyPart.PrivateStateless, statelessBlob.Data);
            partExists = true;
        }
        catch (XmssStateManagerException) { }
        if (partExists)
        {
            throw new XmssStateManagerException("Stateless private part already exists.");
        }

        using var statefulBlob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();
        try
        {
            wrappedStateManager.Load(XmssKeyPart.PrivateStateful, statefulBlob.Data);
            partExists = true;
        }
        catch (XmssStateManagerException) { }
        if (partExists)
        {
            throw new XmssStateManagerException("Stateful private part already exists.");
        }
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="stateManager">TODO</param>
    /// <param name="parameterSet">TODO</param>
    /// <param name="enableIndexObfuscation">TODO</param>
    public void GeneratePrivateKey(IXmssStateManager stateManager, XmssParameterSet parameterSet, bool enableIndexObfuscation)
    {
        ArgumentNullException.ThrowIfNull(stateManager);

        ObjectDisposedException.ThrowIf(IsDisposed, this);

        var wrappedStateManager = new StateManagerWrapper(stateManager);

        // Step 1: Verify that no (possibly valid) private parts exist for the new state.

        VerifyNoPrivateState(wrappedStateManager);

        // Step 2: Cleanup new state (which has no valid private parts anyway).

        wrappedStateManager.DeleteAll();

        XmssError result;

        unsafe
        {
            // Step 3: Create key.

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

            // Step 4: Store state (failure erases any partial storage, then throws).

            try
            {
                wrappedStateManager.Store(XmssKeyPart.PrivateStateless, privateKeyStatelessBlob.Data);
                wrappedStateManager.Store(XmssKeyPart.PrivateStateful, privateKeyStatefulBlob.Data);
            }
            catch (XmssStateManagerException ex)
            {
                wrappedStateManager.DeleteAllAfterFailure(ex);
                throw;
            }

            // Step 5: Replace KeyContext.

            ResetState();
            ParameterSet = parameterSet;
            PrivateKey = new(wrappedStateManager);
            PrivateKey.KeyContext.SwapWith(keyContext);
            PrivateKey.StatefulBlob.SwapWith(privateKeyStatefulBlob);
        }
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="stateManager">TODO</param>
    /// <exception cref="XmssException">TODO</exception>
    public void ImportPrivateKey(IXmssStateManager stateManager)
    {
        ArgumentNullException.ThrowIfNull(stateManager);
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        var wrappedStateManager = new StateManagerWrapper(stateManager);

        XmssError result;

        unsafe
        {
            using var privateKeyStatefulBlob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();
            using var privateKeyStatelessBlob = CriticalXmssPrivateKeyStatelessBlobHandle.Alloc();
            wrappedStateManager.Load(XmssKeyPart.PrivateStateless, privateKeyStatelessBlob.Data);
            wrappedStateManager.Load(XmssKeyPart.PrivateStateful, privateKeyStatefulBlob.Data);

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
                    ResetState();
                    ParameterSet = (XmssParameterSet)oid;
                    PrivateKey = new(wrappedStateManager);
                    PrivateKey.KeyContext.SwapWith(keyContext);
                    PrivateKey.StatefulBlob.SwapWith(privateKeyStatefulBlob);

                    // Now try to load the internal public key part, but failure is not fatal.
                    try
                    {
                        try
                        {
                            using var publicKeyInternalBlob = CriticalXmssPublicKeyInternalBlobHandle.Alloc(XmssCacheType.XMSS_CACHE_TOP, 0,
                                ParameterSet);
                            wrappedStateManager.Load(XmssKeyPart.Public, publicKeyInternalBlob.Data);
                            // The cache will be automatically freed with the key context; we don't need it.
                            XmssInternalCache* cache = null;
                            result = UnsafeNativeMethods.xmss_load_public_key(ref cache, ref PrivateKey.KeyContext.AsRef(),
                                publicKeyInternalBlob.AsRef());
                            XmssException.ThrowIfNotOkay(result);

                            result = UnsafeNativeMethods.xmss_export_public_key(out PublicKey, PrivateKey.KeyContext.AsRef());
                            XmssException.ThrowIfNotOkay(result);
                            HasPublicKey = true;
                        }
                        catch (Exception ex)
                        {
                            throw new IgnoreException(ex);
                        }
                    }
                    catch (IgnoreException) { }
                    return;
                }
            }

            // None of the OIDs worked.
            throw new XmssException(XmssError.XMSS_ERR_INVALID_BLOB);
        }
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="newPartition">TODO</param>
    /// <param name="newPartitionSize">TODO</param>
    public void SplitPrivateKey(IXmssStateManager newPartition, int newPartitionSize)
    {
        ArgumentNullException.ThrowIfNull(newPartition);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(newPartitionSize, 0);

        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ThrowIfNoPrivateKey();

        var wrappedNewPartition = new StateManagerWrapper(newPartition);

        // Step 1: Verify that no (possibly valid) private parts exist for the new state.

        VerifyNoPrivateState(wrappedNewPartition);

        // Step 2: Cleanup new partition (which has no valid private parts anyway).

        wrappedNewPartition.DeleteAll();

        // Step 3: Copy the stateless private part (failure removes any partial copy, then throws)
        try
        {
            using var statelessBlob = CriticalXmssPrivateKeyStatelessBlobHandle.Alloc();
            PrivateKey.WrappedStateManager.Load(XmssKeyPart.PrivateStateless, statelessBlob.Data);
            wrappedNewPartition.Store(XmssKeyPart.PrivateStateless, statelessBlob.Data);
        }
        catch (XmssStateManagerException ex)
        {
            wrappedNewPartition.DeleteAllAfterFailure(ex);
            throw;
        }

        if (HasPublicKey)
        {
            // Step 4: Try to copy the public part (failure removes any partial copy, then throws)
            try
            {
                using var publicBlob = CriticalXmssPublicKeyInternalBlobHandle.Alloc(XmssCacheType.XMSS_CACHE_TOP, 0, ParameterSet);
                PrivateKey.WrappedStateManager.Load(XmssKeyPart.Public, publicBlob.Data);
                wrappedNewPartition.Store(XmssKeyPart.Public, publicBlob.Data);
            }
            catch (XmssStateManagerException ex)
            {
                wrappedNewPartition.DeleteAllAfterFailure(ex);
                throw;
            }
        }

        // Step 5: Try to update the current key context (failure removes the new partition, then throws)
        using var updatedStatefulBlob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();
        using var newStatefulBlob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();
        try
        {
            unsafe
            {
                var result = UnsafeNativeMethods.xmss_partition_signature_space(ref newStatefulBlob.AsPointerRef(),
                    ref updatedStatefulBlob.AsPointerRef(), ref PrivateKey.KeyContext.AsRef(), (uint)newPartitionSize);
                XmssException.ThrowIfNotOkay(result);
            }
        }
        catch (XmssException ex)
        {
            wrappedNewPartition.DeleteAllAfterFailure(ex);
            throw;
        }

        // NOTE: our KeyContext and StateManager are now out of sync! Failure to update the StateManager must destroy the KeyContext!

        // Step 6: Try to store the old (now truncated) partition (failure resets the current key and removes the new partition, then throws)
        try
        {
            PrivateKey.WrappedStateManager.StoreStatefulPart(PrivateKey.StatefulBlob.Data, updatedStatefulBlob.Data);
            PrivateKey.StatefulBlob.SwapWith(updatedStatefulBlob);
        }
        catch (XmssStateManagerException ex)
        {
            ResetState();
            wrappedNewPartition.DeleteAllAfterFailure(ex);
            throw;
        }

        // NOTE: back in sync again

        // Step 7: Try to store the new partition (failure removes the new partition, then throws)
        try
        {
            wrappedNewPartition.Store(XmssKeyPart.PrivateStateful, newStatefulBlob.Data);
        }
        catch (XmssStateManagerException ex)
        {
            wrappedNewPartition.DeleteAllAfterFailure(ex);
            throw;
        }
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="consumedPartition">TODO</param>
    public void MergePartition(IXmssStateManager consumedPartition)
    {
        ArgumentNullException.ThrowIfNull(consumedPartition);

        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ThrowIfNoPrivateKey();

        var wrappedConsumedPartition = new StateManagerWrapper(consumedPartition);

        using var consumedKeyStatefulBlob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();
        wrappedConsumedPartition.Load(XmssKeyPart.PrivateStateful, consumedKeyStatefulBlob.Data);

        using var updatedStatefulBlob = CriticalXmssPrivateKeyStatefulBlobHandle.Alloc();
        unsafe
        {
            var result = UnsafeNativeMethods.xmss_merge_signature_space(ref updatedStatefulBlob.AsPointerRef(),
                ref PrivateKey.KeyContext.AsRef(), consumedKeyStatefulBlob.AsRef());
            XmssException.ThrowIfNotOkay(result);
        }

        // NOTE: our KeyContext and StateManager are now out of sync! Failure to update the StateManager must destroy the KeyContext!

        try
        {
            wrappedConsumedPartition.DeleteAll();
            PrivateKey.WrappedStateManager.StoreStatefulPart(PrivateKey.StatefulBlob.Data, updatedStatefulBlob.Data);
            PrivateKey.StatefulBlob.SwapWith(updatedStatefulBlob);
        }
        catch (XmssStateManagerException)
        {
            ResetState();
            throw;
        }
    }
    #endregion

    #region Public Key
    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="reportPercentage">TODO</param>
    /// <param name="cancellationToken">TODO</param>
    /// <returns>TODO</returns>
    /// <exception cref="InvalidOperationException"></exception>
    public async Task CalculatePublicKeyAsync(Action<double>? reportPercentage = null, CancellationToken cancellationToken = default)
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
                reportPercentage?.Invoke(99.9 * completed / totalTaskCount);
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

            result = UnsafeNativeMethods.xmss_export_public_key(out PublicKey, PrivateKey.KeyContext.AsRef());
            XmssException.ThrowIfNotOkay(result);
            HasPublicKey = true;
        }

        // NOTE: our KeyContext and StateManager are now out of sync, but that does not affect security (only the public part)

        PrivateKey.WrappedStateManager.DeletePublicPart();
        PrivateKey.WrappedStateManager.Store(XmssKeyPart.Public, publicKeyInternalBlob.Data);

        reportPercentage?.Invoke(100.0);
    }
    #endregion Public Key

    #region Sign
    /// <summary>
    /// TODO
    /// </summary>
    public int SignaturesRemaining
    {
        get
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            ThrowIfNoPrivateKey();

            var result = UnsafeNativeMethods.xmss_get_signature_count(out _, out var remainingCount, PrivateKey.KeyContext.AsRef());
            XmssException.ThrowIfNotOkay(result);

            return checked((int)remainingCount);
        }
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="count">TODO</param>
    public void RequestFutureSignatures(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);

        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ThrowIfNoPrivateKey();

        using var privateKeyStatefulBlob = new CriticalXmssPrivateKeyStatefulBlobHandle();
        unsafe
        {
            var result = UnsafeNativeMethods.xmss_request_future_signatures(ref privateKeyStatefulBlob.AsPointerRef(),
                ref PrivateKey.KeyContext.AsRef(), (uint)count);
            XmssException.ThrowIfNotOkay(result);
        }

        // NOTE: our KeyContext and StateManager are now out of sync! Failure to update the StateManager must destroy the KeyContext!

        try
        {
            PrivateKey.WrappedStateManager.StoreStatefulPart(PrivateKey.StatefulBlob.Data, privateKeyStatefulBlob.Data);
            PrivateKey.StatefulBlob.SwapWith(privateKeyStatefulBlob);
        }
        catch (XmssStateManagerException)
        {
            ResetState();
            throw;
        }
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="data">TODO</param>
    /// <returns>TODO</returns>
    public byte[] Sign(ReadOnlySpan<byte> data)
    {
        var signature = new byte[Defines.XMSS_SIGNATURE_SIZE(ParameterSet.AsOID())];
        var bytesWritten = Sign(data, signature);
        XmssException.ThrowFaultDetectedIf(bytesWritten != signature.Length);
        return signature;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="data">TODO</param>
    /// <param name="dataLength">TODO</param>
    /// <returns>TODO</returns>
    public unsafe byte[] Sign(void* data, nuint dataLength)
    {
        var signature = new byte[Defines.XMSS_SIGNATURE_SIZE(ParameterSet.AsOID())];
        var bytesWritten = Sign(data, dataLength, signature);
        XmssException.ThrowFaultDetectedIf(bytesWritten != signature.Length);
        return signature;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="data">TODO</param>
    /// <param name="destination">TODO</param>
    /// <returns>TODO</returns>
    /// <exception cref="ArgumentException">TODO</exception>
    public int Sign(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        return TrySign(data, destination, out var bytesWritten) ? bytesWritten
            : throw new ArgumentException("Destination is too short.");
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="data">TODO</param>
    /// <param name="dataLength">TODO</param>
    /// <param name="destination">TODO</param>
    /// <returns>TODO</returns>
    /// <exception cref="ArgumentException">TODO</exception>
    public unsafe int Sign(void* data, nuint dataLength, Span<byte> destination)
    {
        return TrySign(data, dataLength, destination, out var bytesWritten) ? bytesWritten
            : throw new ArgumentException("Destination is too short.");
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="data">TODO</param>
    /// <param name="destination">TODO</param>
    /// <param name="bytesWritten">TODO</param>
    /// <returns>TODO</returns>
    public bool TrySign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
    {
        unsafe
        {
            fixed (byte* dataPtr = data)
            {
                return TrySign(dataPtr, (nuint)data.Length, destination, out bytesWritten);
            }
        }
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="data">TODO</param>
    /// <param name="dataLength">TODO</param>
    /// <param name="destination">TODO</param>
    /// <param name="bytesWritten">TODO</param>
    /// <returns>TODO</returns>
    public unsafe bool TrySign(void* data, nuint dataLength, Span<byte> destination, out int bytesWritten)
    {
        if (data is null)
        {
            throw new ArgumentNullException(nameof(data));
        }
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ThrowIfNoPrivateKey();

        if (destination.Length < Defines.XMSS_SIGNATURE_SIZE(ParameterSet.AsOID()))
        {
            bytesWritten = 0;
            return false;
        }

        XmssError result;

        using var signatureBlob = new CriticalXmssSignatureBlobHandle();
        // First attempt: use any previously requested signature.
        result = UnsafeNativeMethods.xmss_sign_message(ref signatureBlob.AsPointerRef(), ref PrivateKey.KeyContext.AsRef(),
            new() { data = (byte*)data, data_size = dataLength });
        if (result == XmssError.XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE)
        {
            // Seconds attempt: request a single signature.
            RequestFutureSignatures(1);
            result = UnsafeNativeMethods.xmss_sign_message(ref signatureBlob.AsPointerRef(), ref PrivateKey.KeyContext.AsRef(),
                new() { data = (byte*)data, data_size = dataLength });
        }
        XmssException.ThrowIfNotOkay(result);
        XmssException.ThrowFaultDetectedIf(signatureBlob.AsRef().data_size > (nuint)destination.Length);
        var signature = new ReadOnlySpan<byte>(signatureBlob.AsRef().data, (int)signatureBlob.AsRef().data_size);
        signature.CopyTo(destination);
        bytesWritten = signature.Length;
        return true;
    }
    #endregion

    #region Verify
    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="data">TODO</param>
    /// <param name="signature">TODO</param>
    /// <returns>TODO</returns>
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

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="data">TODO</param>
    /// <param name="signature">TODO</param>
    /// <returns>TODO</returns>
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
    #endregion

    const int AsnPublicKeyLength = 70;
    const int SubjectPublicKeyInfoLength = 85;
    const string XmssPublicKeyLabel = "XMSS PUBLIC KEY";
    const string PublicKeyLabel = "PUBLIC KEY";
    const string CertificateLabel = "CERTIFICATE";

    #region Export
    /// <summary>
    /// TODO
    /// </summary>
    /// <returns>TODO</returns>
    public byte[] ExportRfcPublicKey()
    {
        var result = new byte[Defines.XMSS_PUBLIC_KEY_SIZE];
        XmssException.ThrowFaultDetectedIf(!TryExportRfcPublicKey(result, out var bytesWritten));
        XmssException.ThrowFaultDetectedIf(bytesWritten != Defines.XMSS_PUBLIC_KEY_SIZE);
        return result;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <returns>TODO</returns>
    public byte[] ExportAsnPublicKey()
    {
        var result = new byte[AsnPublicKeyLength];
        XmssException.ThrowFaultDetectedIf(!TryExportAsnPublicKey(result, out var bytesWritten));
        XmssException.ThrowFaultDetectedIf(bytesWritten != AsnPublicKeyLength);
        return result;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <returns>TODO</returns>
    [Obsolete("XMSS public keys as standalone ASN.1 PEM are not standardized; consider using ExportSubjectPublicKeyInfoPem() instead.")]
    public string ExportAsnPublicKeyPem()
    {
        // Line endings may differ on different platforms; length will be somewhere between 2x and 3x the binary form.
        var result = new char[3 * AsnPublicKeyLength];
        XmssException.ThrowFaultDetectedIf(!TryExportAsnPublicKeyPem(result, out var charsWritten));
        return new(result[..charsWritten]);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <returns>TODO</returns>
    public override byte[] ExportSubjectPublicKeyInfo()
    {
        var result = new byte[SubjectPublicKeyInfoLength];
        XmssException.ThrowFaultDetectedIf(!TryExportSubjectPublicKeyInfo(result, out var bytesWritten));
        XmssException.ThrowFaultDetectedIf(bytesWritten != SubjectPublicKeyInfoLength);
        return result;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="destination">TODO</param>
    /// <param name="bytesWritten">TODO</param>
    /// <returns>TODO</returns>
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

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="destination">TODO</param>
    /// <param name="bytesWritten">TODO</param>
    /// <returns>TODO</returns>
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

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="destination">TODO</param>
    /// <param name="charsWritten">TODO</param>
    /// <returns>TODO</returns>
    [Obsolete("XMSS public keys as standalone ASN.1 PEM are not standardized; consider using TryExportSubjectPublicKeyInfoPem() instead.")]
    public bool TryExportAsnPublicKeyPem(Span<char> destination, out int charsWritten)
    {
        return PemEncoding.TryWrite(XmssPublicKeyLabel, ExportAsnPublicKey(), destination, out charsWritten);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="destination">TODO</param>
    /// <param name="bytesWritten">TODO</param>
    /// <returns>TODO</returns>
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
    #endregion

    #region Import
    [StackTraceHidden]
    static void ThrowIfUnsupportedAlgorithmOid(Oid algorithmOid)
    {
        if (algorithmOid.Value != IdAlgXmssHashsig.Value)
        {
            throw new CryptographicException($"Invalid public key algorithm OID ({algorithmOid.Value}), expected {IdAlgXmssHashsig.Value}.");
        }
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
        ResetState();
        PublicKey = publicKey;
        ParameterSet = parameterSet;
        HasPublicKey = true;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="input">TODO</param>
    /// <exception cref="ArgumentException">TODO</exception>
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

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="source">TODO</param>
    /// <param name="bytesRead">TODO</param>
    public void ImportRfcPublicKey(ReadOnlySpan<byte> source, out int bytesRead)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        DecodeXmssPublicKey(source, out var publicKey, out var parameterSet, out bytesRead, false);
        ImportXmssPublicKey(parameterSet, publicKey);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="source">TODO</param>
    /// <param name="bytesRead">TODO</param>
    public void ImportAsnPublicKey(ReadOnlySpan<byte> source, out int bytesRead)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        DecodeAsnPublicKey(source, out var publicKey, out var parameterSet, out var bytesConsumed, false);
        ImportXmssPublicKey(parameterSet, publicKey);
        bytesRead = bytesConsumed;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="source">TODO</param>
    /// <param name="bytesRead">TODO</param>
    public override void ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source, out int bytesRead)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        DecodeSubjectPublicKeyInfo(source, out var publicKey, out var parameterSet, out var bytesConsumed, false);
        ImportXmssPublicKey(parameterSet, publicKey);
        bytesRead = bytesConsumed;
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="publicKey">TODO</param>
    public void ImportCertificatePublicKey(PublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        ThrowIfUnsupportedAlgorithmOid(publicKey.Oid);
        DecodeXmssPublicKey(publicKey.EncodedKeyValue.RawData, out var xmssPublicKey, out var parameterSet, out var _, true);
        ImportXmssPublicKey(parameterSet, xmssPublicKey);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="certificate">TODO</param>
    public void ImportCertificatePublicKey(X509Certificate certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        ThrowIfUnsupportedAlgorithmOid(new(certificate.GetKeyAlgorithm()));
        DecodeXmssPublicKey(certificate.GetPublicKey(), out var publicKey, out var parameterSet, out var _, true);
        ImportXmssPublicKey(parameterSet, publicKey);
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="certificate">TODO</param>
    public void ImportCertificatePublicKey(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ObjectDisposedException.ThrowIf(IsDisposed, this);

        ImportCertificatePublicKey(certificate.PublicKey);
    }
    #endregion
}
