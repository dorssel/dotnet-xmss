// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

class Xmss
{
    // XMSS-SHA2_10_256
    const int n = 32;
    // unused: const int w = 16;
    const int len = 67;
    const int h = 10;

    static readonly byte[] toByte_1_32 = 1.toByte(32);
    static readonly byte[] toByte_2_32 = 2.toByte(32);

    /// <summary>
    /// Hash function
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-5.1">RFC 8391, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key</param>
    /// <param name="M">message</param>
    /// <returns>SHA2-256(toByte(1, 32) || KEY || M)</returns>
    static byte[] H(byte[] KEY, params byte[][] M)
    {
        Debug.Assert(KEY.Length == n);
        Debug.Assert(M.Sum(m => m.Length) == 2 * n);

        using var hash = SHA256.Create();
        hash.TransformBlock(toByte_1_32);
        hash.TransformBlock(KEY);
        foreach (var m in M)
        {
            hash.TransformBlock(m);
        }
        hash.TransformFinalBlock(Array.Empty<byte>());
        return hash.Hash;
    }

    /// <summary>
    /// Hash function
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-5.1">RFC 8391, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key (array of 3 instances of n-byte keys)</param>
    /// <param name="M">message (possibly in segments)</param>
    /// <returns>SHA2-256(toByte(2, 32) || KEY || M)</returns>
    static byte[] H_msg(byte[][] KEY, params byte[][] M)
    {
        Debug.Assert(KEY.Length == 3);
        Debug.Assert(KEY.All(k => k.Length == n));

        using var hash = SHA256.Create();
        hash.TransformBlock(toByte_2_32);
        hash.TransformBlock(KEY[0]);
        hash.TransformBlock(KEY[1]);
        hash.TransformBlock(KEY[2]);
        foreach (var m in M)
        {
            hash.TransformBlock(m);
        }
        hash.TransformFinalBlock(Array.Empty<byte>());
        return hash.Hash;
    }

    /// <summary>
    /// Algorithm 7: Randomized Tree Hashing
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-4.1.4">RFC 8391, Section 4.1.4</see>
    /// </summary>
    /// <param name="LEFT">n-byte value</param>
    /// <param name="RIGHT">n-byte value</param>
    /// <param name="SEED">seed</param>
    /// <param name="ADRS">address</param>
    /// <returns>n-byte randomized hash</returns>
    static byte[] RAND_HASH(byte[] LEFT, byte[] RIGHT, byte[] SEED, Address ADRS)
    {
        Debug.Assert(LEFT.Length == n);
        Debug.Assert(RIGHT.Length == n);
        Debug.Assert(SEED.Length == n);

        ADRS.keyAndMask = 0;
        var KEY = Wots.PRF(SEED, ADRS);
        ADRS.keyAndMask = 1;
        var BM_0 = Wots.PRF(SEED, ADRS);
        ADRS.keyAndMask = 2;
        var BM_1 = Wots.PRF(SEED, ADRS);

        BM_0.xor_InPlace(LEFT);
        BM_1.xor_InPlace(RIGHT);

        return H(KEY, BM_0, BM_1);
    }

    /// <summary>
    /// Algorithm 8: L-Trees
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-4.1.5">RFC 8391, Section 4.1.5</see>
    /// <para/>
    /// NOTE: The order of the parameters listed in the text is different from the order
    /// used in the pseudocode; we use the order of the pseudocode.
    /// </summary>
    /// <param name="pk">WOTS+ public key</param>
    /// <param name="ADRS">address</param>
    /// <param name="SEED">seed</param>
    /// <returns>n-byte compressed public key value</returns>
    static byte[] ltree(byte[][] pk, byte[] SEED, Address ADRS)
    {
        Debug.Assert(SEED.Length == n);

        var lenPrime = len;
        ADRS.tree_height = 0;
        while (lenPrime > 1)
        {
            for (var i = 0; i < lenPrime / 2; i++)
            {
                ADRS.tree_index = i;
                pk[i] = RAND_HASH(pk[2 * i], pk[2 * i + 1], SEED, ADRS);
            }
            if (lenPrime % 2 == 1)
            {
                pk[lenPrime / 2] = pk[lenPrime - 1];
            }
            lenPrime = (lenPrime + 1) / 2; // ceil(len' / 2)
            ADRS.tree_height++;
        }
        return pk[0];
    }

    /// <summary>
    /// Algorithm 9: TreeHash
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-4.1.6">RFC 8391, Section 4.1.6</see>
    /// </summary>
    /// <param name="SK">XMSS private key</param>
    /// <param name="s">start index</param>
    /// <param name="t">target node height</param>
    /// <param name="ADRS">address</param>
    /// <returns>n-byte root node - top node on Stack</returns>
    internal static byte[] treeHash(XmssPrivateKey SK, int s, int t, Address ADRS)
    {
        Debug.Assert(s >= 0);
        Debug.Assert(t >= 0);
        Debug.Assert(s % (1 << t) == 0);

        // NOTE: We also push the height of the node, as it is needed in the while loop.
        var Stack = new Stack<(byte[] node, int tree_height)>();

        for (var i = 0; i < (1 << t); i++)
        {
            var SEED = SK.getSEED();
            ADRS.type = AddressType.OTS;
            ADRS.OTS_address = s + i;
            var pk = Wots.WOTS_genPK(SK.getWOTS_SK(s + i), SEED, ADRS);
            ADRS.type = AddressType.L_tree;
            ADRS.L_tree_address = s + i;
            var node = ltree(pk, SEED, ADRS);
            ADRS.type = AddressType.Hash_tree;
            ADRS.tree_height = 0;
            ADRS.tree_index = i + s;
            while (Stack.Count > 0 && Stack.Peek().tree_height == ADRS.tree_height)
            {
                ADRS.tree_index = (ADRS.tree_index - 1) / 2;
                node = RAND_HASH(Stack.Pop().node, node, SEED, ADRS);
                ADRS.tree_height++;
            }
            Stack.Push((node, ADRS.tree_height));
        }
        return Stack.Pop().node;
    }

    /// <summary>
    /// Algorithm 10: XMSS Key Generation
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-4.1.7">RFC 8391, Section 4.1.7</see>
    /// </summary>
    /// <returns>XMSS private key SK, XMSS public key PK</returns>
    public static (XmssPrivateKey, XmssPublicKey) XMSS_keyGen()
    {
        // This gets relayed to the Algorithm 10' from NIST SP 800-208, Section 7.2.1,
        // as required by Section 6.2.
        return XmssMT.XMSS_keyGen(0, 0, null);
    }

    /// <summary>
    /// (Example) buildAuth
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-4.1.9">RFC 8391, Section 4.1.9</see>
    /// </summary>
    /// <param name="SK">XMSS private key</param>
    /// <param name="i">WOTS+ key pair index</param>
    /// <param name="ADRS">address</param>
    /// <returns>Authentication path</returns>
    static byte[][] buildAuth(XmssPrivateKey SK, int i, Address ADRS)
    {
        var auth = new byte[h][];
        for (var j = 0; j < h; j++)
        {
            var k = (i / 2) ^ 1;
            auth[j] = treeHash(SK, k * (1 << j), j, ADRS);
        }
        return auth;
    }

    /// <summary>
    /// Algorithm 11: Generate a WOTS+ signature on a message with corresponding authentication path
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-4.1.9">RFC 8391, Section 4.1.9</see>
    /// </summary>
    /// <param name="Mprime">n-byte message M'</param>
    /// <param name="SK">XMSS private key</param>
    /// <param name="idx_sig">signature index</param>
    /// <param name="ADRS">address</param>
    /// <returns>Concatenation of WOTS+ signature sig_ots and authentication path auth</returns>
    static (byte[][] sig_ots, byte[][] auth) treeSig(byte[] Mprime, XmssPrivateKey SK, int idx_sig, Address ADRS)
    {
        var auth = buildAuth(SK, idx_sig, ADRS);
        ADRS.type = AddressType.OTS;
        ADRS.OTS_address = idx_sig;
        var sig_ots = Wots.WOTS_sign(SK.getWOTS_SK(idx_sig), Mprime, SK.getSEED(), ADRS);
        return (sig_ots, auth);
    }

    /// <summary>
    /// Algorithm 12: Generate an XMSS signature and update the XMSS private key
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-4.1.9">RFC 8391, Section 4.1.9</see>
    /// <para/>
    /// NOTE: The XMMS private key (SK) is modified in place instead of returned.
    /// It is the responsibility of the caller to <em>first</em> persist the updated
    /// private key (SK) before using/releasing the returned signature.
    /// </summary>
    /// <param name="M">Message M</param>
    /// <param name="SK">XMSS private key</param>
    /// <returns>XMSS signature Sig</returns>
    public static XmssSignature XMSS_sign(byte[] M, XmssPrivateKey SK)
    {
        var idx_sig = SK.idx_sig++;
        var ADRS = new Address();
        var r = Wots.PRF(SK.getSK_PRF(), idx_sig.toByte(32));
        var Mprime = H_msg(new byte[][] { r, SK.getRoot(), idx_sig.toByte(n) }, M);
        var (sig_ots, auth) = treeSig(Mprime, SK, idx_sig, ADRS);
        return new(idx_sig, r, sig_ots, auth);
    }

    /// <summary>
    /// Algorithm 13: Compute a root node from a tree signature
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-4.1.10">RFC 8391, Section 4.1.10</see>
    /// </summary>
    /// <param name="idx_sig">index</param>
    /// <param name="sig_ots">WOTS+ signature</param>
    /// <param name="auth">authentication path</param>
    /// <param name="Mprime">n-byte message</param>
    /// <param name="SEED">seed</param>
    /// <param name="ADRS">address</param>
    /// <returns>n-byte root value</returns>
    internal static byte[] XMSS_rootFromSig(int idx_sig, byte[][] sig_ots, byte[][] auth, byte[] Mprime, byte[] SEED, Address ADRS)
    {
        ADRS.type = AddressType.OTS;
        ADRS.OTS_address = idx_sig;
        var pk_ots = Wots.WOTS_pkFromSig(sig_ots, Mprime, SEED, ADRS);

        ADRS.type = AddressType.L_tree;
        ADRS.L_tree_address = idx_sig;
        byte[] node; ;
        node = ltree(pk_ots, SEED, ADRS);
        ADRS.type = AddressType.Hash_tree;
        ADRS.tree_index = idx_sig;
        for (var k = 0; k < h; k++)
        {
            ADRS.tree_height = k;
            ADRS.tree_index /= 2;
            node = RAND_HASH(node, auth[k], SEED, ADRS);
        }
        return node;
    }

    /// <summary>
    /// Algorithm 14: Verify an XMSS signature using the corresponding XMSS public key and a message
    /// <para/>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-4.1.10">RFC 8391, Section 4.1.10</see>
    /// </summary>
    /// <param name="Sig">XMSS signature</param>
    /// <param name="M">message</param>
    /// <param name="PK">XMSS public key</param>
    /// <returns>Boolean</returns>
    public static bool XMSS_verify(XmssSignature Sig, byte[] M, XmssPublicKey PK)
    {
        var ADRS = new Address();
        var Mprime = H_msg(new byte[][] { Sig.r, PK.getRoot(), Sig.idx_sig.toByte(n) }, M);
        var node = XMSS_rootFromSig(Sig.idx_sig, Sig.sig_ots, Sig.auth, Mprime, PK.getSEED(), ADRS);
        return CryptographicOperations.FixedTimeEquals(node, PK.getRoot());
    }
}
