// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

public interface IXmss
{
    public Version NativeHeadersVersion { get; }

    public Version NativeLibraryVersion { get; }

    public bool HasPrivateKey { get; }

    public bool HasPublicKey { get; }

    public void GeneratePrivateKey(IXmssStateManager stateManager, XmssParameterSet parameterSet, bool enableIndexObfuscation);

    public Task GeneratePublicKeyAsync(Action<double>? reportPercentage = null, CancellationToken cancellationToken = default);

    public void ImportPrivateKey(IXmssStateManager stateManager);

    public byte[] Sign(ReadOnlySpan<byte> data);

    public int Sign(ReadOnlySpan<byte> data, Span<byte> destination);

    public bool TrySign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten);

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    public bool Verify(Stream data, ReadOnlySpan<byte> signature);
}
