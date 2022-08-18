// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

sealed class Xmss
    : IDisposable
{
    public Xmss(XmssOid xmssOid)
    {
        Parameters = XmssParameters.Lookup(xmssOid);

        toByte_1 = 1.toByte(Parameters.Wots.toByteLength);
        toByte_2 = 2.toByte(Parameters.Wots.toByteLength);

        Wots = new(Parameters.Wots.OID);
    }

    readonly XmssParameters Parameters;
    readonly Wots Wots;
    readonly byte[] toByte_1 = 1.toByte(32);
    readonly byte[] toByte_2 = 2.toByte(32);

    #region IDisposable

    bool IsDisposed;

    public void Dispose()
    {
        if (!IsDisposed)
        {
            Wots.Dispose();
            IsDisposed = true;
        }
    }

    #endregion

    /// <summary>
    /// Hash function
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key</param>
    /// <param name="M">message</param>
    /// <returns>HashAlgorithm(toByte(1, toBytesLength) || KEY || M)</returns>
    byte[] H(byte[] KEY, params byte[][] M)
    {
        Debug.Assert(KEY.Length == Parameters.Wots.n);
        Debug.Assert(M.Sum(m => m.Length) == 2 * Parameters.Wots.n);

        Wots.HashAlgorithm.TransformBlock(toByte_1);
        Wots.HashAlgorithm.TransformBlock(KEY);
        foreach (var m in M)
        {
            Wots.HashAlgorithm.TransformBlock(m);
        }
        Wots.HashAlgorithm.TransformFinalBlock(Array.Empty<byte>());
        return Wots.T(Wots.HashAlgorithm.Hash);
    }

    /// <summary>
    /// Hash function
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 5.1</see>
    /// </summary>
    /// <param name="KEY">key (array of 3 instances of n-byte keys)</param>
    /// <param name="M">message (possibly in segments)</param>
    /// <returns>HashAlgorithm(toByte(2, toByteLength) || KEY || M)</returns>
    byte[] H_msg(byte[][] KEY, params byte[][] M)
    {
        Debug.Assert(KEY.Length == 3);
        Debug.Assert(KEY.All(k => k.Length == Parameters.Wots.n));

        Wots.HashAlgorithm.TransformBlock(toByte_2);
        Wots.HashAlgorithm.TransformBlock(KEY[0]);
        Wots.HashAlgorithm.TransformBlock(KEY[1]);
        Wots.HashAlgorithm.TransformBlock(KEY[2]);
        foreach (var m in M)
        {
            Wots.HashAlgorithm.TransformBlock(m);
        }
        Wots.HashAlgorithm.TransformFinalBlock(Array.Empty<byte>());
        return Wots.T(Wots.HashAlgorithm.Hash);
    }

    /// <summary>
    /// Algorithm 7: Randomized Tree Hashing
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 4.1.4</see>
    /// </summary>
    /// <param name="LEFT">n-byte value</param>
    /// <param name="RIGHT">n-byte value</param>
    /// <param name="SEED">seed</param>
    /// <param name="ADRS">address</param>
    /// <returns>n-byte randomized hash</returns>
    byte[] RAND_HASH(byte[] LEFT, byte[] RIGHT, byte[] SEED, Address ADRS)
    {
        Debug.Assert(LEFT.Length == Parameters.Wots.n);
        Debug.Assert(RIGHT.Length == Parameters.Wots.n);
        Debug.Assert(SEED.Length == Parameters.Wots.n);

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
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 4.1.5</see>
    /// <para/>
    /// NOTE: The order of the parameters listed in the text is different from the order
    /// used in the pseudocode; we use the order of the pseudocode.
    /// </summary>
    /// <param name="pk">WOTS+ public key</param>
    /// <param name="ADRS">address</param>
    /// <param name="SEED">seed</param>
    /// <returns>n-byte compressed public key value</returns>
    byte[] ltree(byte[][] pk, byte[] SEED, Address ADRS)
    {
        Debug.Assert(SEED.Length == Parameters.Wots.n);

        var lenPrime = Parameters.Wots.len;
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
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 4.1.6</see>
    /// </summary>
    /// <param name="SK">XMSS private key</param>
    /// <param name="s">start index</param>
    /// <param name="t">target node height</param>
    /// <param name="ADRS">address</param>
    /// <returns>n-byte root node - top node on Stack</returns>
    byte[] treeHash(XmssPrivateKey SK, int s, int t, Address ADRS)
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
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 4.1.7</see>
    /// <para/>
    /// NOTE: This uses the default .NET <see cref="RandomNumberGenerator"/>, which may not be NIST approved.
    /// </summary>
    /// <returns>XMSS private key SK, XMSS public key PK</returns>
    public (XmssPrivateKey, XmssPublicKey) XMSS_keyGen()
    {
        using var rng = RandomNumberGenerator.Create();
        return XMSS_keyGen(rng);
    }

    /// <summary>
    /// Algorithm 10: XMSS Key Generation
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 4.1.7</see>
    /// <para/>
    /// This will request 3 times n random bytes (for S_XMSS, SK_PRF, and SEED) in
    /// separate invocations. This allows the RNG to use fresh entropy on each
    /// invocation if it is configured to do so.
    /// </summary>
    /// <param name="rng">An approved random bit generator, see NIST SP 800-208, Secton 6.2.</param>
    /// <returns>XMSS private key SK, XMSS public key PK</returns>
    public (XmssPrivateKey, XmssPublicKey) XMSS_keyGen(RandomNumberGenerator rng)
    {
        // WOTS key generation as required by NIST SP 800-208, Section 6.2.
        // See also NIST SP 800-208, Algorithm 10'.
        var S_XMSS = new byte[Parameters.Wots.n];
        var SK_PRF = new byte[Parameters.Wots.n];
        var SEED = new byte[Parameters.Wots.n];

        rng.GetBytes(S_XMSS);
        rng.GetBytes(SK_PRF);
        rng.GetBytes(SEED);

        var SK = new XmssPrivateKey(Parameters.OID);
        SK.setS_XMSS(S_XMSS);
        SK.setSK_PRF(SK_PRF);
        SK.setSEED(SEED);

        var root = treeHash(SK, 0, Parameters.h, new());
        SK.setRoot(root);

        return (SK, new XmssPublicKey(Parameters.OID, root, SEED));
    }

    /// <summary>
    /// (Example) buildAuth
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 4.1.9</see>
    /// </summary>
    /// <param name="SK">XMSS private key</param>
    /// <param name="i">WOTS+ key pair index</param>
    /// <param name="ADRS">address</param>
    /// <returns>Authentication path</returns>
    byte[][] buildAuth(XmssPrivateKey SK, int i, Address ADRS)
    {
        var auth = new byte[Parameters.h][];
        for (var j = 0; j < Parameters.h; j++)
        {
            var k = (i / (1 << j)) ^ 1;
            auth[j] = treeHash(SK, k * (1 << j), j, ADRS);
        }
        return auth;
    }

    /// <summary>
    /// Algorithm 11: Generate a WOTS+ signature on a message with corresponding authentication path
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 4.1.9</see>
    /// </summary>
    /// <param name="Mprime">n-byte message M'</param>
    /// <param name="SK">XMSS private key</param>
    /// <param name="idx_sig">signature index</param>
    /// <param name="ADRS">address</param>
    /// <returns>Concatenation of WOTS+ signature sig_ots and authentication path auth</returns>
    (byte[][] sig_ots, byte[][] auth) treeSig(byte[] Mprime, XmssPrivateKey SK, int idx_sig, Address ADRS)
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
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 4.1.9</see>
    /// <para/>
    /// NOTE: The XMMS private key (SK) is modified in place instead of returned.
    /// It is the responsibility of the caller to <em>first</em> persist the updated
    /// private key (SK) before using/releasing the returned signature.
    /// </summary>
    /// <param name="M">Message M</param>
    /// <param name="SK">XMSS private key</param>
    /// <returns>XMSS signature Sig</returns>
    public XmssSignature XMSS_sign(byte[] M, XmssPrivateKey SK)
    {
        var idx_sig = SK.idx_sig++;
        var r = Wots.PRF(SK.getSK_PRF(), idx_sig.toByte(32));
        var Mprime = H_msg(new byte[][] { r, SK.getRoot(), idx_sig.toByte(Parameters.Wots.n) }, M);
        var (sig_ots, auth) = treeSig(Mprime, SK, idx_sig, new());
        return new(idx_sig, r, sig_ots, auth);
    }

    /// <summary>
    /// Algorithm 13: Compute a root node from a tree signature
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 4.1.10</see>
    /// </summary>
    /// <param name="idx_sig">index</param>
    /// <param name="sig_ots">WOTS+ signature</param>
    /// <param name="auth">authentication path</param>
    /// <param name="Mprime">n-byte message</param>
    /// <param name="SEED">seed</param>
    /// <param name="ADRS">address</param>
    /// <returns>n-byte root value</returns>
    byte[] XMSS_rootFromSig(int idx_sig, byte[][] sig_ots, byte[][] auth, byte[] Mprime, byte[] SEED, Address ADRS)
    {
        ADRS.type = AddressType.OTS;
        ADRS.OTS_address = idx_sig;
        var pk_ots = Wots.WOTS_pkFromSig(sig_ots, Mprime, SEED, ADRS);

        ADRS.type = AddressType.L_tree;
        ADRS.L_tree_address = idx_sig;
        var node = ltree(pk_ots, SEED, ADRS);
        ADRS.type = AddressType.Hash_tree;
        ADRS.tree_index = idx_sig;
        for (var k = 0; k < Parameters.h; k++)
        {
            ADRS.tree_height = k;
            ADRS.tree_index /= 2;
            node = (idx_sig & (1 << k)) == 0
                ? RAND_HASH(node, auth[k], SEED, ADRS)
                : RAND_HASH(auth[k], node, SEED, ADRS);
        }
        return node;
    }

    /// <summary>
    /// Algorithm 14: Verify an XMSS signature using the corresponding XMSS public key and a message
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 4.1.10</see>
    /// </summary>
    /// <param name="Sig">XMSS signature</param>
    /// <param name="M">message</param>
    /// <param name="PK">XMSS public key</param>
    /// <returns>Boolean</returns>
    public bool XMSS_verify(XmssSignature Sig, byte[] M, XmssPublicKey PK)
    {
        var Mprime = H_msg(new byte[][] { Sig.r, PK.getRoot(), Sig.idx_sig.toByte(Parameters.Wots.n) }, M);
        var node = XMSS_rootFromSig(Sig.idx_sig, Sig.sig_ots, Sig.auth, Mprime, PK.getSEED(), new());
        return CryptographicOperations.FixedTimeEquals(node, PK.getRoot());
    }
}
