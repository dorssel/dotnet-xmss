// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

class XmssSignature
{
    public XmssSignature(int idx_sig, byte[] r, byte[][] sig_ots, byte[][] auth)
    {
        this.idx_sig = idx_sig;
        this.r = r;
        this.sig_ots = sig_ots;
        this.auth = auth;
    }

    /// <summary>
    /// index
    /// </summary>
    public int idx_sig;

    /// <summary>
    /// randomness [n]
    /// </summary>
    public byte[] r { get; set; }

    /// <summary>
    /// WOTS+ signature [len,n]
    /// </summary>
    public byte[][] sig_ots;

    /// <summary>
    /// authentication path [h,n]
    /// </summary>
    public byte[][] auth;
}
