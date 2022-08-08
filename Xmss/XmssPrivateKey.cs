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

    public byte[][] getWOTS_SK(int i)
    {
        return _WOTS_SK[i];
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
