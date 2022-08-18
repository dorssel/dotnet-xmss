// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;

namespace Dorssel.Security.Cryptography;

sealed class XmssPrivateKey
{
    public XmssPrivateKey(XmssOid xmssOid)
    {
        XmssParameters = XmssParameters.Lookup(xmssOid);
        WotsParameters = WotsParameters.Lookup(XmssParameters.WotsOID);
    }

    public XmssParameters XmssParameters { get; }

    public WotsParameters WotsParameters { get; }

    public int idx_sig { get; set; }

    byte[] _S_XMSS = null!;
    public void setS_XMSS(byte[] S_XMSS)
    {
        Debug.Assert(S_XMSS.Length == WotsParameters.n);

        _S_XMSS = S_XMSS;
    }

    byte[] _SK_PRF = null!;
    public byte[] getSK_PRF() => (byte[])_SK_PRF.Clone();
    public void setSK_PRF(byte[] SK_PRF)
    {
        Debug.Assert(SK_PRF.Length == WotsParameters.n);

        _SK_PRF = SK_PRF;
    }

    byte[] _SEED = null!;
    public byte[] getSEED() => (byte[])_SEED.Clone();
    public void setSEED(byte[] SEED)
    {
        Debug.Assert(SEED.Length == WotsParameters.n);

        _SEED = SEED;
    }

    /// <summary>
    /// WOTS key generation as required by NIST SP 800-208, Section 6.2.
    /// See also NIST SP 800-208, Algorithm 10'.
    /// <para/>
    /// <see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 4.1.3</see>
    /// </summary>
    /// <param name="i"></param>
    /// <returns>the i^th WOTS+ private key</returns>
    public byte[][] getWOTS_SK(int i)
    {
        using var wots = new Wots(WotsParameters.OID);
        return wots.WOTS_genSK(_S_XMSS, _SEED, new() { OTS_address = i });
    }

    byte[] _root = null!;
    public byte[] getRoot() => (byte[])_root.Clone();
    public void setRoot(byte[] root)
    {
        _root = root;
    }
}
