// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

/// <summary>
/// See:
/// <list type="bullet">
/// <item><see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 5.2</see></item>
/// <item><see href="https://doi.org/10.6028/NIST.SP.800-208">NIST SP 800-208, Section 5</see></item>
/// <item><see href="https://www.iana.org/assignments/xmss-extended-hash-based-signatures/xmss-extended-hash-based-signatures.xhtml#wots-signatures">IANA, XMSS: Extended Hash-Based Signatures</see></item>
/// </list>
/// NOTE: Some parameter sets are RFC only, some NIST only, and a few conform to both. All are defined by IANA.
/// </summary>
enum WotsOid
{
    WOTSP_SHA2_256 = 0x00000001,
    WOTSP_SHA2_512,
    WOTSP_SHAKE_256,
    WOTSP_SHAKE_512,
    WOTSP_SHA2_192,
    WOTSP_SHAKE256_256,
    WOTSP_SHAKE256_192,
}
