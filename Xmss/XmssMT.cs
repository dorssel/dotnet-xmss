// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

#if false

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

class XmssMT
{
    // XMSS-SHA2_10_256
    const int n = 32;
    // unused: const int w = 16;
    const int len = 67;
    const int h = 10;
    const int d = 1;

    static readonly byte[] toByte_4_32 = 4.toByte(32);

    /// <summary>
    /// Pseudo-Random Function
    /// <para/>
    /// NOTE: We use M = SEED || ADRS
    /// <para/>
    /// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf">NIST SP 800-208, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key</param>
    /// <param name="SEED">seed</param>
    /// <param name="ADRS">address</param>
    /// <returns>SHA2-256(toByte(4, 32) || KEY || SEED || ADRS)</returns>
    static byte[] PRF_keygen(byte[] KEY, byte[] SEED, Address ADRS)
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

    /// <summary>
    /// Algorithm 10': Modified XMSS Key Generation Algorithm
    /// <para/>
    /// NOTE: As with RFC 8391, we return both private and public keys.
    /// <para/>
    /// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf">NIST SP 800-208, Section 4.1.7</see>
    /// </summary>
    /// <param name="L">level</param>
    /// <param name="t">tree</param>
    /// <param name="PK_MT">public key of top-level tree (if L ≠ d - 1)</param>
    /// <returns>XMSS private key SK, XMSS public key PK</returns>
    public static (XmssPrivateKey, XmssPublicKey) XMSS_keyGen(int L, int t, XmssPublicKey? PK_MT)
    {
        Debug.Assert(0 <= L && L < d);
        Debug.Assert(0 <= t && t < (1 << ((d - 1 - L) * (h / d))));
        Debug.Assert((PK_MT is null) == (L == 0));

        var SK = new XmssPrivateKey();
        using var rng = RandomNumberGenerator.Create();

        var S_XMSS = new byte[n];
        rng.GetBytes(S_XMSS);
        SK.setS_XMSS(S_XMSS);

        byte[] SEED;
        if (L == d - 1)
        {
            SEED = new byte[n];
            rng.GetBytes(SEED);
            SK.setSEED(SEED);
        }
        else
        {
            SEED = PK_MT!.getSEED();
        }

        var ADRS = new Address
        {
            layer_address = L,
            tree_address = t
        };

        SK.idx_sig = t * (1 << (h / d));
        var wots_sk = new byte[1 << (h / d)][][];
        for (var i = 0; i < (1 << (h / d)); i++)
        {
            ADRS.OTS_address = i;
            var sk = new byte[len][];
            for (var j = 0; j < len; j++)
            {
                ADRS.chain_address = j;
                sk[j] = XmssPrivateKey.PRF_keygen(S_XMSS, SEED, ADRS);
            }
            wots_sk[i] = sk;
        }
        //SK.setWOTS_SK(wots_sk);

        var SK_PRF = new byte[n];
        rng.GetBytes(SK_PRF);
        SK.setSK_PRF(SK_PRF);

        var root = Xmss.treeHash(SK, 0, h, ADRS);

        // TODO: handle L and t for MT.

        SK.setRoot(root);
        return (SK, new XmssPublicKey(XmssOid.XMSS_SHA2_10_256, root, SEED));
    }
}

#endif
