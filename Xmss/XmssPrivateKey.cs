// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

class XmssPrivateKey
{
    // XMSS-SHA2_10_256
    const int n = 32;
    // unused: const int w = 16;
    const int len = 67; // len_1 + len_2;

    static readonly byte[] toByte_4_32 = 4.toByte(32);

    /// <summary>
    /// Pseudo-Random Function
    /// <para/>
    /// NOTE: We use M = SEED || ADRS
    /// <para/>
    /// <see href="https://csrc.nist.gov/publications/detail/sp/800-208/final">NIST SP 800-208, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key</param>
    /// <param name="SEED">seed</param>
    /// <param name="ADRS">address</param>
    /// <returns>SHA2-256(toByte(4, 32) || KEY || SEED || ADRS)</returns>
    internal static byte[] PRF_keygen(byte[] KEY, byte[] SEED, Address ADRS)
    {
        Debug.Assert(KEY.Length == n);
        Debug.Assert(SEED.Length == n);

        using var hash = SHA256.Create();
        hash.TransformBlock(toByte_4_32);
        hash.TransformBlock(KEY);
        hash.TransformBlock(SEED);
        hash.TransformFinalBlock(ADRS.ToBytes());
        return hash.Hash;
    }

    public int idx_sig { get; set; }

    byte[] _S_XMSS = null!;
    public void setS_XMSS(byte[] S_XMSS)
    {
        Debug.Assert(S_XMSS.Length == n);

        _S_XMSS = S_XMSS;
    }

    byte[] _SK_PRF = null!;
    public byte[] getSK_PRF() => (byte[])_SK_PRF.Clone();
    public void setSK_PRF(byte[] SK_PRF)
    {
        Debug.Assert(SK_PRF.Length == n);

        _SK_PRF = SK_PRF;
    }

    byte[] _SEED = null!;
    public byte[] getSEED() => (byte[])_SEED.Clone();
    public void setSEED(byte[] SEED)
    {
        Debug.Assert(SEED.Length == n);

        _SEED = SEED;
    }

    /// <summary>
    /// WOTS key generation as required by NIST SP 800-208, Section 6.2.
    /// See also NIST SP 800-208, Algorithm 10'.
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-4.1.3">RFC 8391, Section 4.1.3</see>
    /// </summary>
    /// <param name="i"></param>
    /// <returns>the i^th WOTS+ private key</returns>
    public byte[][] getWOTS_SK(int i)
    {
        var ADRS = new Address()
        {
            OTS_address = i,
        };
        var sk = new byte[len][];
        for (var j = 0; j < len; j++)
        {
            ADRS.chain_address = j;
            sk[j] = PRF_keygen(_S_XMSS, _SEED, ADRS);
        }
        return sk;
    }

    byte[] _root = null!;
    public byte[] getRoot() => (byte[])_root.Clone();
    public void setRoot(byte[] root)
    {
        _root = root;
    }
}
