// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

sealed record XmssParameters
{
    XmssParameters()
    {
    }

    public XmssOid OID { get; private init; }
    public WotsOid WotsOID { get; private init; }
    public int h { get; private init; }

    static readonly XmssParameters[] All =
    [
        new()
        {
            OID = XmssOid.XMSS_SHA2_10_256,
            WotsOID = WotsOid.WOTSP_SHA2_256,
            h = 10,
        },
        new()
        {
            OID = XmssOid.XMSS_SHA2_16_256,
            WotsOID = WotsOid.WOTSP_SHA2_256,
            h = 16,
        },
        new()
        {
            OID = XmssOid.XMSS_SHA2_20_256,
            WotsOID = WotsOid.WOTSP_SHA2_256,
            h = 20,
        },
        new()
        {
            OID = XmssOid.XMSS_SHA2_10_512,
            WotsOID = WotsOid.WOTSP_SHA2_512,
            h = 10,
        },
        new()
        {
            OID = XmssOid.XMSS_SHA2_16_512,
            WotsOID = WotsOid.WOTSP_SHA2_512,
            h = 16,
        },
        new()
        {
            OID = XmssOid.XMSS_SHA2_20_512,
            WotsOID = WotsOid.WOTSP_SHA2_512,
            h = 20,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE_10_256,
            WotsOID = WotsOid.WOTSP_SHAKE_256,
            h = 10,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE_16_256,
            WotsOID = WotsOid.WOTSP_SHAKE_256,
            h = 16,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE_20_256,
            WotsOID = WotsOid.WOTSP_SHAKE_256,
            h = 20,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE_10_512,
            WotsOID = WotsOid.WOTSP_SHAKE_512,
            h = 10,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE_16_512,
            WotsOID = WotsOid.WOTSP_SHAKE_512,
            h = 16,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE_20_512,
            WotsOID = WotsOid.WOTSP_SHAKE_512,
            h = 20,
        },
        new()
        {
            OID = XmssOid.XMSS_SHA2_10_192,
            WotsOID = WotsOid.WOTSP_SHA2_192,
            h = 10,
        },
        new()
        {
            OID = XmssOid.XMSS_SHA2_16_192,
            WotsOID = WotsOid.WOTSP_SHA2_192,
            h = 16,
        },
        new()
        {
            OID = XmssOid.XMSS_SHA2_20_192,
            WotsOID = WotsOid.WOTSP_SHA2_192,
            h = 20,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE256_10_256,
            WotsOID = WotsOid.WOTSP_SHAKE256_256,
            h = 10,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE256_16_256,
            WotsOID = WotsOid.WOTSP_SHAKE256_256,
            h = 16,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE256_20_256,
            WotsOID = WotsOid.WOTSP_SHAKE256_256,
            h = 20,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE256_10_192,
            WotsOID = WotsOid.WOTSP_SHAKE256_192,
            h = 10,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE256_16_192,
            WotsOID = WotsOid.WOTSP_SHAKE256_192,
            h = 16,
        },
        new()
        {
            OID = XmssOid.XMSS_SHAKE256_20_192,
            WotsOID = WotsOid.WOTSP_SHAKE256_192,
            h = 20,
        },
    ];

    public static XmssParameters Lookup(XmssOid OID)
    {
        return All[(int)OID - 1];
    }
}
