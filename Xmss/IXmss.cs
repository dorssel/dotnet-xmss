// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

public interface IXmss
{
    public Version NativeHeadersVersion { get; }

    public Version NativeLibraryVersion { get; }

    public bool Verify(Stream data, byte[] signature);

    public void GeneratePrivateKey(XmssParameterSet parameterSet);
}
