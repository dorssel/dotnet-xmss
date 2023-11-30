// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

sealed class SHAKE(int securityBits, int digestSize)
        : HashAlgorithm
{
    readonly Waher.Security.SHA3.Keccak1600 BaseHashAlgorithm = securityBits switch
    {
        128 => new Waher.Security.SHA3.SHAKE128(digestSize),
        256 => new Waher.Security.SHA3.SHAKE256(digestSize),
        _ => throw new ArgumentException($"Invalid SHAKE bitsize", nameof(securityBits)),
    };
    readonly MemoryStream Stream = new();

    public override void Initialize()
    {
        Stream.SetLength(0);
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize)
    {
        Stream.Write(array, ibStart, cbSize);
    }

    protected override byte[] HashFinal()
    {
        Stream.Position = 0;
        var result = BaseHashAlgorithm.ComputeVariable(Stream);
        Stream.SetLength(0);
        return result;
    }
}
