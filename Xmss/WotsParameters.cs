// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

record WotsParameters
{
    private WotsParameters()
    {
        // All currently defined parameter use hexadecimal digits.
        w = 16;
        // All currently defined parameter sets require 3 checksum digits.
        len_2 = 3;
    }

    public WotsOid OID { get; private init; }
    public int n { get; private init; }
    public int len { get; private init; }
    public int w { get; private init; }
    public int len_1 => len - len_2;
    public int len_2 { get; private init; }

    public Func<HashAlgorithm> HashAlgorithm { get; private init; } = null!;
    public int toByteLength { get; private set; }

    static readonly WotsParameters[] All = new WotsParameters[]
    {
        new()
        {
            OID = WotsOid.WOTSP_SHA2_256,
            n = 32,
            len = 67,
            HashAlgorithm = () => SHA256.Create(),
            toByteLength = 32,
        },
        new()
        {
            OID = WotsOid.WOTSP_SHA2_512,
            n = 64,
            len = 131,
            HashAlgorithm = () => SHA512.Create(),
            toByteLength = 64,
        },
        new()
        {
            OID = WotsOid.WOTSP_SHAKE_256,
            n = 32,
            len = 67,
            HashAlgorithm = () => new SHAKE(128, 256),
            toByteLength = 32,
        },
        new()
        {
            OID = WotsOid.WOTSP_SHAKE_512,
            n = 64,
            len = 131,
            HashAlgorithm = () => new SHAKE(256, 512),
            toByteLength = 64,
        },
        new()
        {
            OID = WotsOid.WOTSP_SHA2_192,
            n = 24,
            len = 51,
            HashAlgorithm = () => SHA256.Create(),
            toByteLength = 4,
        },
        new()
        {
            OID = WotsOid.WOTSP_SHAKE256_256,
            n = 32,
            len = 67,
            HashAlgorithm = () => new SHAKE(256, 256),
            toByteLength = 32,
        },
        new()
        {
            OID = WotsOid.WOTSP_SHAKE256_192,
            n = 24,
            len = 51,
            HashAlgorithm = () => new SHAKE(256, 192),
            toByteLength = 4,
        },
    };

    public static WotsParameters Lookup(WotsOid OID)
    {
        return All[(int)OID - 1];
    }
}
