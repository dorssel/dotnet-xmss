// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

sealed class XmssPublicKey
{
    public XmssPublicKey(XmssOid OID, byte[] root, byte[] SEED)
    {
        // this.OID = OID;
        _ = OID;
        this.root = (byte[])root.Clone();
        this.SEED = (byte[])SEED.Clone();
    }

    // unused: public XmssOid OID { get; }

    readonly byte[] root;
    readonly byte[] SEED;

    public byte[] getRoot()
    {
        return (byte[])root.Clone();
    }

    public byte[] getSEED()
    {
        return (byte[])SEED.Clone();
    }

    public byte[] ToBytes()
    {
        return [.. root, .. SEED];
    }
}
