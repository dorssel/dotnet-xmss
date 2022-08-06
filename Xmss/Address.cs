// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// Hash Function Address Scheme
/// <para/>
/// See <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-2.5">RFC 8391, Section 2.5</see>.
/// </summary>
class Address
{
    public int layer_address { get; set; }

    public long tree_address { get; set; }

    AddressType _type;
    public AddressType type
    {
        get => _type;

        set
        {
            _type = value;
            OTS_address = 0;
            chain_address = 0;
            hash_address = 0;
            keyAndMask = 0;
        }
    }

    // OTS accessors

    public int OTS_address { get; set; }
    public int chain_address { get; set; }
    public int hash_address { get; set; }
    public int keyAndMask { get; set; }

    // L-tree accessors

    public int L_tree_address { get => OTS_address; set => OTS_address = value; }
    public int tree_height { get => chain_address; set => chain_address = value; }
    public int tree_index { get => hash_address; set => hash_address = value; }

    static void WriteBigEndian(long value, byte[] array, int endOffset)
    {
        Debug.Assert(value >= 0);

        while (value > 0)
        {
            array[endOffset--] = unchecked((byte)value);
            value >>= 8;
        }
    }

    public byte[] ToBytes()
    {
        var result = new byte[32];
        WriteBigEndian(layer_address, result, 3);
        WriteBigEndian(tree_address, result, 11);
        WriteBigEndian((int)_type, result, 15);
        WriteBigEndian(OTS_address, result, 19);
        WriteBigEndian(chain_address, result, 23);
        WriteBigEndian(hash_address, result, 27);
        WriteBigEndian(keyAndMask, result, 31);
        return result;
    }
}
