// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

/// <summary>
/// See:
/// <list type="bullet">
/// <item><see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 5.3</see></item>
/// <item><see href="https://doi.org/10.6028/NIST.SP.800-208">NIST SP 800-208, Sections 5.1 to 5.4</see></item>
/// <item><see href="https://www.iana.org/assignments/xmss-extended-hash-based-signatures/xmss-extended-hash-based-signatures.xhtml#xmss-signatures">IANA, XMSS: Extended Hash-Based Signatures</see></item>
/// </list>
/// NOTE: Some parameter sets are RFC only, some NIST only, and a few conform to both. All are defined by IANA.
/// </summary>
enum XmssOid
{
    XMSS_SHA2_10_256 = 0x00000001,
    XMSS_SHA2_16_256,
    XMSS_SHA2_20_256,
    XMSS_SHA2_10_512,
    XMSS_SHA2_16_512,
    XMSS_SHA2_20_512,
    XMSS_SHAKE_10_256,
    XMSS_SHAKE_16_256,
    XMSS_SHAKE_20_256,
    XMSS_SHAKE_10_512,
    XMSS_SHAKE_16_512,
    XMSS_SHAKE_20_512,
    XMSS_SHA2_10_192,
    XMSS_SHA2_16_192,
    XMSS_SHA2_20_192,
    XMSS_SHAKE256_10_256,
    XMSS_SHAKE256_16_256,
    XMSS_SHAKE256_20_256,
    XMSS_SHAKE256_10_192,
    XMSS_SHAKE256_16_192,
    XMSS_SHAKE256_20_192,
}
