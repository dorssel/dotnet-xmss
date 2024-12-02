// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

public interface IXmss
{
    public Version NativeHeadersVersion { get; }

    public Version NativeLibraryVersion { get; }

    public void GeneratePrivateKey(IXmssStateManager stateManager, XmssParameterSet parameterSet, bool enableIndexObfuscation);

    public void ImportPrivateKey(IXmssStateManager stateManager);

    public byte[] Sign(ReadOnlySpan<byte> data);

    public int Sign(ReadOnlySpan<byte> data, Span<byte> destination);

    public bool TrySign(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten);

    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    public bool Verify(Stream data, ReadOnlySpan<byte> signature);
}
