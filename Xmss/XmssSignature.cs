// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

sealed class XmssSignature(int idx_sig, byte[] r, byte[][] sig_ots, byte[][] auth)
{
    /// <summary>
    /// index
    /// </summary>
    public int idx_sig = idx_sig;

    /// <summary>
    /// randomness [n]
    /// </summary>
    public byte[] r { get; set; } = r;

    /// <summary>
    /// WOTS+ signature [len,n]
    /// </summary>
    public byte[][] sig_ots = sig_ots;

    /// <summary>
    /// authentication path [h,n]
    /// </summary>
    public byte[][] auth = auth;

    public byte[] ToBytes()
    {
        return
            [.. idx_sig.toByte(4), .. r, .. sig_ots.SelectMany(i => i), .. auth.SelectMany(i => i)];
    }
}
