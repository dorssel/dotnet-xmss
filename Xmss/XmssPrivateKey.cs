// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;

namespace Dorssel.Security.Cryptography;

class XmssPrivateKey
{
    // XMSS-SHA2_10_256
    const int n = 32;
    // unused: const int w = 16;
    // unused: const int len = 67; // len_1 + len_2;

    public int idx_sig { get; set; }

    byte[] _S_XMSS = null!;
    public byte[] getS_XMSS() => (byte[])_S_XMSS.Clone();
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

    byte[][][] _WOTS_SK = null!;
    public byte[][] getWOTS_SK(int i)
    {
        return _WOTS_SK[i];
    }
    public void setWOTS_SK(byte[][][] wots_sk)
    {
        _WOTS_SK = wots_sk;
    }

    byte[] _root = null!;
    public byte[] getRoot() => (byte[])_root.Clone();
    public void setRoot(byte[] root)
    {
        _root = root;
    }
}
