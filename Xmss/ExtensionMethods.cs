// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

static class ExtensionMethods
{
    /// <summary>
    /// TransformBlock() is an <see cref="ICryptoTransform"/> method that is also used for encryption/decryption.
    /// When used with hashing algorithms the output is just a copy of the input and therefore not needed. As a consequence,
    /// the return value is also not useful.
    /// <para/>
    /// This helper function makes the code more readable; it hides the output parameters and the return value.
    /// Additionally, it assumes the entire input array is used as input, which is true everywhere we use it.
    /// </summary>
    public static void TransformBlock(this HashAlgorithm hashAlgorithm, byte[] inputBuffer)
    {
        _ = hashAlgorithm.TransformBlock(inputBuffer, 0, inputBuffer.Length, null, 0);
    }

    /// <summary>
    /// TransformFinalBlock() is an <see cref="ICryptoTransform"/> method that is also used for encryption/decryption.
    /// When used with hashing algorithms the output is just a copy of the input and therefore not needed. As a consequence,
    /// the return value is also not useful.
    /// <para/>
    /// This helper function makes the code more readable; it hides the output parameters and the return value.
    /// Additionally, it assumes the entire input array is used as input, which is true everywhere we use it.
    /// </summary>
    public static void TransformFinalBlock(this HashAlgorithm hashAlgorithm, byte[] inputBuffer)
    {
        _ = hashAlgorithm.TransformFinalBlock(inputBuffer, 0, inputBuffer.Length);
    }

    /// <summary>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 2.4</see>
    /// </summary>
    /// <param name="x">integer</param>
    /// <param name="y">number of bytes</param>
    /// <returns>y-byte string containing the binary representation of x in big-endian byte order</returns>
    public static byte[] toByte(this int x, int y)
    {
        Debug.Assert(x >= 0);
        Debug.Assert(y >= 4);

        var Z = new byte[y];
        Z[Z.Length - 1] = unchecked((byte)x);
        Z[Z.Length - 2] = unchecked((byte)(x >> 8));
        Z[Z.Length - 3] = unchecked((byte)(x >> 16));
        Z[Z.Length - 4] = unchecked((byte)(x >> 24));
        return Z;
    }

    // See: NIST SP 800-38B, Section 4.2.2
    //
    // In place: X = (X xor Y)
    public static void xor_InPlace(this byte[] X, byte[] Y)
    {
        Debug.Assert(X.Length == Y.Length);

        for (var i = 0; i < X.Length; ++i)
        {
            X[i] ^= Y[i];
        }
    }

    public static WotsOid ToWotsOid(this XmssOid xmssOid) => (WotsOid)((((int)xmssOid) - 1) / 3 + 1);
}
