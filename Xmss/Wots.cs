// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

sealed class Wots
    : IDisposable
{
    public Wots(WotsOid wotsOid)
    {
        Parameters = WotsParameters.Lookup(wotsOid);

        HashAlgorithm = Parameters.HashAlgorithm();

        toByte_0 = 0.toByte(Parameters.toByteLength);
        toByte_3 = 3.toByte(Parameters.toByteLength);
        toByte_4 = 4.toByte(Parameters.toByteLength);
    }

    readonly WotsParameters Parameters;
    public HashAlgorithm HashAlgorithm { get; private init; }
    readonly byte[] toByte_0;
    readonly byte[] toByte_3;
    readonly byte[] toByte_4;

    #region IDisposable

    bool IsDisposed;

    public void Dispose()
    {
        if (!IsDisposed)
        {
            HashAlgorithm.Dispose();
            IsDisposed = true;
        }
    }

    #endregion

    public byte[] T(byte[] hashValue)
    {
        Debug.Assert(Parameters.n <= hashValue.Length);

        return hashValue.Length == Parameters.n ? hashValue : hashValue.Take(Parameters.n).ToArray();
    }

    /// <summary>
    /// Hash function
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key</param>
    /// <param name="M">message</param>
    /// <returns>HashAlgorithm(toByte((0, toByteLength) || KEY || M)</returns>
    byte[] F(byte[] KEY, byte[] M)
    {
        Debug.Assert(KEY.Length == Parameters.n);
        Debug.Assert(M.Length == Parameters.n);

        HashAlgorithm.TransformBlock(toByte_0);
        HashAlgorithm.TransformBlock(KEY);
        HashAlgorithm.TransformFinalBlock(M);
        return T(HashAlgorithm.Hash);
    }

    /// <summary>
    /// Pseudo-Random Function
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key</param>
    /// <param name="M">32-byte message ("index")</param>
    /// <returns>HashAlgorithm(toByte(3, toByteLength) || KEY || M)</returns>
    public byte[] PRF(byte[] KEY, byte[] M)
    {
        Debug.Assert(KEY.Length == Parameters.n);
        Debug.Assert(M.Length == 32);

        HashAlgorithm.TransformBlock(toByte_3);
        HashAlgorithm.TransformBlock(KEY);
        HashAlgorithm.TransformFinalBlock(M);
        return T(HashAlgorithm.Hash);
    }

    /// <summary>
    /// Pseudo-Random Function
    /// <para/>
    /// NOTE: Specialization for strongly typed ADRS.
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key</param>
    /// <param name="ADRS">address</param>
    /// <returns>HashAlgorithm(toByte(3, toByteLength) || KEY || ADRS)</returns>
    public byte[] PRF(byte[] KEY, Address ADRS) => PRF(KEY, ADRS.ToBytes());

    /// <summary>
    /// Pseudo-Random Function
    /// <para/>
    /// NOTE: We use M = SEED || ADRS
    /// <para/>
    /// <see href="https://doi.org/10.6028/NIST.SP.800-208">NIST SP 800-208, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key</param>
    /// <param name="SEED">seed</param>
    /// <param name="ADRS">address</param>
    /// <returns>HashAlgorithm(toByte(4, toByteLength) || KEY || SEED || ADRS)</returns>
    byte[] PRF_keygen(byte[] KEY, byte[] SEED, Address ADRS)
    {
        Debug.Assert(KEY.Length == Parameters.n);
        Debug.Assert(SEED.Length == Parameters.n);

        HashAlgorithm.TransformBlock(toByte_4);
        HashAlgorithm.TransformBlock(KEY);
        HashAlgorithm.TransformBlock(SEED);
        HashAlgorithm.TransformFinalBlock(ADRS.ToBytes());
        return T(HashAlgorithm.Hash);
    }

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
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 2.6</see>
    /// </summary>
    /// <param name="X">byte string</param>
    /// <returns>int array basew</returns>
    int[] base_w_with_csum(byte[] X)
    {
        Debug.Assert(X.Length == Parameters.n);

        var basew = new int[Parameters.len];
        var csum = Parameters.len_1 * (Parameters.w - 1);
        for (var i = 0; i < Parameters.n; i++)
        {
            csum -= basew[2 * i] = X[i] >> 4;
            csum -= basew[2 * i + 1] = X[i] & 0xf;
        }

        // Append csum (also in base w)
        for (var i = 0; i < Parameters.len_2; i++)
        {
            basew[Parameters.len - 1 - i] = csum & 0xf;
            csum >>= 4;
        }

        return basew;
    }

    /// <summary>
    /// Algorithm 2: Chaining Function
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 3.1.2</see>
    /// </summary>
    /// <param name="X">Input string</param>
    /// <param name="i">start index</param>
    /// <param name="s">number of steps</param>
    /// <param name="SEED">seed</param>
    /// <param name="ADRS">address</param>
    /// <returns>value of F iterated s times on X</returns>
    byte[] chain(byte[] X, int i, int s, byte[] SEED, Address ADRS)
    {
        Debug.Assert(X.Length == Parameters.n);
        Debug.Assert(i >= 0);
        Debug.Assert(s >= 0);
        Debug.Assert(i + s < Parameters.w);
        Debug.Assert(SEED.Length == Parameters.n);

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

#if false
    /// <summary>
    /// Algorithm 3: Generating a WOTS+ Private Key
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 3.1.3</see>
    /// <para/>
    /// NOTE: This function is defined for completeness. It is never actually used, as XMSS instead
    /// uses the WOTS key generation required by NIST SP 800-208, Section 6.2.
    /// </summary>
    /// <returns>WOTS+ private key sk</returns>
    public byte[][] WOTS_genSK()
    {
        using var rng = RandomNumberGenerator.Create();

        var sk = new byte[Parameters.len][];
        for (var i = 0; i < Parameters.len; i++)
        {
            sk[i] = new byte[Parameters.n];
            rng.GetBytes(sk[i]);
        }
        return sk;
    }
#endif

    /// <summary>
    /// Algorithm 3': Generating a WOTS+ Private Key
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 3.1.3</see>
    /// <para/>
    /// NOTE: This method of WOTS+ key generation is required by
    /// <see href="https://doi.org/10.6028/NIST.SP.800-208">NIST SP 800-208, Section 6.2</see>.
    /// </summary>
    /// <returns>WOTS+ private key sk</returns>
    public byte[][] WOTS_genSK(byte[] S_XMSS, byte[] SEED, Address ADRS)
    {
        Debug.Assert(S_XMSS.Length == Parameters.n);
        Debug.Assert(SEED.Length == Parameters.n);

        ADRS.hash_address = 0;
        ADRS.keyAndMask = 0;

        var sk = new byte[Parameters.len][];
        for (var j = 0; j < Parameters.len; j++)
        {
            ADRS.chain_address = j;
            sk[j] = PRF_keygen(S_XMSS, SEED, ADRS);
        }
        return sk;
    }

    /// <summary>
    /// Algorithm 4: Generating a WOTS+ Public Key From a Private Key
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 3.1.4</see>
    /// <para/>
    /// NOTE: The order of the parameters listed in the text is different from the order
    /// used in the pseudocode; we use the order of the pseudocode.
    /// </summary>
    /// <param name="sk">WOTS+ private key</param>
    /// <param name="SEED">seed</param>
    /// <param name="ADRS">address</param>
    /// <returns>WOTS+ public key pk</returns>
    public byte[][] WOTS_genPK(byte[][] sk, byte[] SEED, Address ADRS)
    {
        Debug.Assert(sk.Length == Parameters.len);
        Debug.Assert(sk.All(sk_i => sk_i.Length == Parameters.n));
        Debug.Assert(SEED.Length == Parameters.n);

        var pk = new byte[Parameters.len][];
        for (var i = 0; i < Parameters.len; i++)
        {
            ADRS.chain_address = i;
            pk[i] = chain(sk[i], 0, Parameters.w - 1, SEED, ADRS);
        }
        return pk;
    }

    /// <summary>
    /// Algorithm 5: Generating a signature from a private key and a message
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 3.1.5</see>
    /// <para/>
    /// NOTE: The order of the parameters listed in the text is different from the order
    /// used in the pseudocode; we use the order of the pseudocode.
    /// </summary>
    /// <param name="sk">WOTS+ private key</param>
    /// <param name="M">Message</param>
    /// <param name="ADDR">address</param>
    /// <param name="SEED">seed</param>
    /// <returns>WOTS+ signature sig</returns>
    public byte[][] WOTS_sign(byte[][] sk, byte[] M, byte[] SEED, Address ADRS)
    {
        Debug.Assert(M.Length == Parameters.n);
        Debug.Assert(sk.Length == Parameters.len);
        Debug.Assert(sk.All(sk_i => sk_i.Length == Parameters.n));
        Debug.Assert(SEED.Length == Parameters.n);

        var msg = base_w_with_csum(M);

        var sig = new byte[Parameters.len][];
        for (var i = 0; i < Parameters.len; i++)
        {
            ADRS.chain_address = i;
            sig[i] = chain(sk[i], 0, msg[i], SEED, ADRS);
        }
        return sig;
    }

    /// <summary>
    /// Algorithm 6: Computing a WOTS+ public key from a message and its signature
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 3.1.6</see>
    /// <para/>
    /// NOTE: The order of the parameters listed in the text is different from the order
    /// used in the pseudocode; we use the order of the pseudocode.
    /// </summary>
    /// <param name="M">Message</param>
    /// <param name="sig">WOTS+ signature</param>
    /// <param name="ADDR">address</param>
    /// <param name="SEED">seed</param>
    /// <returns>'Temporary' WOTS+ public key tmp_pk</returns>
    public byte[][] WOTS_pkFromSig(byte[][] sig, byte[] M, byte[] SEED, Address ADRS)
    {
        Debug.Assert(M.Length == Parameters.n);
        Debug.Assert(sig.Length == Parameters.len);
        Debug.Assert(sig.All(sig_i => sig_i.Length == Parameters.n));
        Debug.Assert(SEED.Length == Parameters.n);

        var msg = base_w_with_csum(M);

        var tmp_pk = new byte[Parameters.len][];
        for (var i = 0; i < Parameters.len; i++)
        {
            ADRS.chain_address = i;
            tmp_pk[i] = chain(sig[i], msg[i], Parameters.w - 1 - msg[i], SEED, ADRS);
        }
        return tmp_pk;
    }
}
