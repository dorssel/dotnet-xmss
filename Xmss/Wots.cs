// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

class Wots
{
    // WOTSP-SHA2_256
    const int n = 32;
    const int w = 16;
    const int len = 67; // len_1 + len_2;

    const int len_1 = 64; // ceil(8n / lg(w))
    const int len_2 = 3; // floor(lg(len_1 * (w - 1)) / lg(w)) + 1

    static readonly byte[] toByte_0_32 = 0.toByte(32);
    static readonly byte[] toByte_3_32 = 3.toByte(32);

    /// <summary>
    /// Hash function
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-5.1">RFC 8391, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key</param>
    /// <param name="M">message</param>
    /// <returns>SHA2-256(toByte(0, 32) || KEY || M)</returns>
    static byte[] F(byte[] KEY, byte[] M)
    {
        Debug.Assert(KEY.Length == n);
        Debug.Assert(M.Length == n);

        using var hash = SHA256.Create();
        hash.TransformBlock(toByte_0_32);
        hash.TransformBlock(KEY);
        hash.TransformFinalBlock(M);
        return hash.Hash;
    }

    /// <summary>
    /// Pseudo-Random Function
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-5.1">RFC 8391, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key</param>
    /// <param name="M">32-byte message ("index")</param>
    /// <returns>SHA2-256(toByte(3, 32) || KEY || M)</returns>
    public static byte[] PRF(byte[] KEY, byte[] M)
    {
        Debug.Assert(KEY.Length == n);
        Debug.Assert(M.Length == n);

        using var hash = SHA256.Create();
        hash.TransformBlock(toByte_3_32);
        hash.TransformBlock(KEY);
        hash.TransformFinalBlock(M);
        return hash.Hash;
    }

    /// <summary>
    /// Pseudo-Random Function
    /// <para/>
    /// NOTE: Specialization for strongly typed ADRS.
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-5.1">RFC 8391, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key</param>
    /// <param name="ADRS">address</param>
    /// <returns>SHA2-256(toByte(3, 32) || KEY || ADRS)</returns>
    public static byte[] PRF(byte[] KEY, Address ADRS) => PRF(KEY, ADRS.ToBytes());

    /// <summary>
    /// Algorithm 1: base_w
    /// <para/>
    /// Modified from original:
    /// <list type="bullet">
    /// <item>X has length n</item>
    /// <item>Appends csum at end</item>
    /// <item>output has length len</item>
    /// </list>
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-2.6">RFC 8391, Section 2.6</see>
    /// </summary>
    /// <param name="X">byte string</param>
    /// <returns>int array basew</returns>
    static int[] base_w_with_csum(byte[] X)
    {
        Debug.Assert(X.Length == n);

        var basew = new int[len];
        var csum = len_1 * (w - 1);
        for (var i = 0; i < n; i++)
        {
            csum -= basew[2 * i] = X[i] >> 4;
            csum -= basew[2 * i + 1] = X[i] & 0xf;
        }

        // Append csum (also in base w)
        for (var i = 0; i < len_2; i++)
        {
            basew[len - 1 - i] = csum & 0xf;
            csum >>= 4;
        }

        return basew;
    }

    /// <summary>
    /// Algorithm 2: Chaining Function
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-3.1.2">RFC 8391, Section 3.1.2</see>
    /// </summary>
    /// <param name="X">Input string</param>
    /// <param name="i">start index</param>
    /// <param name="s">number of steps</param>
    /// <param name="SEED">seed</param>
    /// <param name="ADRS">address</param>
    /// <returns>value of F iterated s times on X</returns>
    static byte[] chain(byte[] X, int i, int s, byte[] SEED, Address ADRS)
    {
        Debug.Assert(X.Length == n);
        Debug.Assert(i >= 0);
        Debug.Assert(s >= 0);
        Debug.Assert(i + s < w);
        Debug.Assert(SEED.Length == n);

        // non-recursive version of the RFC 8391 algorithm

        var tmp = X;
        for (var j = 0; j < s; j++)
        {
            ADRS.hash_address = i + j;
            ADRS.keyAndMask = 0;
            var KEY = PRF(SEED, ADRS);
            ADRS.keyAndMask = 1;
            var BM = PRF(SEED, ADRS);

            // NOTE: Reverse the role of BM and tmp (twice), so we don't modify the initial input X.
            // This prevents having to clone X.
            BM.xor_InPlace(tmp);
            tmp = F(KEY, BM);
        }
        return tmp;
    }

    /// <summary>
    /// Algorithm 3: Generating a WOTS+ Private Key
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-3.1.3">RFC 8391, Section 3.1.3</see>
    /// <para/>
    /// NOTE: This function is defined for completeness. It is never actually used, as XMSS instead
    /// uses the WOTS key generation required by NIST SP 800-208, Section 6.2.
    /// </summary>
    /// <returns>WOTS+ private key sk</returns>
    public static byte[][] WOTS_genSK()
    {
        using var rng = RandomNumberGenerator.Create();

        var sk = new byte[len][];
        for (var i = 0; i < len; i++)
        {
            sk[i] = new byte[n];
            rng.GetBytes(sk[i]);
        }
        return sk;
    }

    /// <summary>
    /// Algorithm 4: Generating a WOTS+ Public Key From a Private Key
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-3.1.4">RFC 8391, Section 3.1.4</see>
    /// <para/>
    /// NOTE: The order of the parameters listed in the text is different from the order
    /// used in the pseudocode; we use the order of the pseudocode.
    /// </summary>
    /// <param name="sk">WOTS+ private key</param>
    /// <param name="SEED">seed</param>
    /// <param name="ADRS">address</param>
    /// <returns>WOTS+ public key pk</returns>
    public static byte[][] WOTS_genPK(byte[][] sk, byte[] SEED, Address ADRS)
    {
        Debug.Assert(sk.Length == len);
        Debug.Assert(sk.All(sk_i => sk_i.Length == n));
        Debug.Assert(SEED.Length == n);

        var pk = new byte[len][];
        for (var i = 0; i < len; i++)
        {
            ADRS.chain_address = i;
            pk[i] = chain(sk[i], 0, w - 1, SEED, ADRS);
        }
        return pk;
    }

    /// <summary>
    /// Algorithm 5: Generating a signature from a private key and a message
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-3.1.5">RFC 8391, Section 3.1.5</see>
    /// <para/>
    /// NOTE: The order of the parameters listed in the text is different from the order
    /// used in the pseudocode; we use the order of the pseudocode.
    /// </summary>
    /// <param name="sk">WOTS+ private key</param>
    /// <param name="M">Message</param>
    /// <param name="ADDR">address</param>
    /// <param name="SEED">seed</param>
    /// <returns>WOTS+ signature sig</returns>
    public static byte[][] WOTS_sign(byte[][] sk, byte[] M, byte[] SEED, Address ADRS)
    {
        Debug.Assert(M.Length == n);
        Debug.Assert(sk.Length == len);
        Debug.Assert(sk.All(sk_i => sk_i.Length == n));
        Debug.Assert(SEED.Length == n);

        var msg = base_w_with_csum(M);

        var sig = new byte[len][];
        for (var i = 0; i < len; i++)
        {
            ADRS.chain_address = i;
            sig[i] = chain(sk[i], 0, msg[i], SEED, ADRS);
        }
        return sig;
    }

    /// <summary>
    /// Algorithm 6: Computing a WOTS+ public key from a message and its signature
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-3.1.6">RFC 8391, Section 3.1.6</see>
    /// <para/>
    /// NOTE: The order of the parameters listed in the text is different from the order
    /// used in the pseudocode; we use the order of the pseudocode.
    /// </summary>
    /// <param name="M">Message</param>
    /// <param name="sig">WOTS+ signature</param>
    /// <param name="ADDR">address</param>
    /// <param name="SEED">seed</param>
    /// <returns>'Temporary' WOTS+ public key tmp_pk</returns>
    public static byte[][] WOTS_pkFromSig(byte[][] sig, byte[] M, byte[] SEED, Address ADRS)
    {
        Debug.Assert(M.Length == n);
        Debug.Assert(sig.Length == len);
        Debug.Assert(sig.All(sig_i => sig_i.Length == n));
        Debug.Assert(SEED.Length == n);

        var msg = base_w_with_csum(M);

        var tmp_pk = new byte[len][];
        for (var i = 0; i < len; i++)
        {
            ADRS.chain_address = i;
            tmp_pk[i] = chain(sig[i], msg[i], w - 1 - msg[i], SEED, ADRS);
        }
        return tmp_pk;
    }
}
