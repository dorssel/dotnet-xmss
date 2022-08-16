// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

/// <summary>
/// See:
/// <list type="bullet">
/// <item><see href="https://doi.org/10.17487/RFC8391">RFC 8391, Section 5.4</see></item>
/// <item><see href="https://doi.org/10.6028/NIST.SP.800-208">NIST SP 800-208, Sections 5.1 to 5.4</see></item>
/// <item><see href="https://www.iana.org/assignments/xmss-extended-hash-based-signatures/xmss-extended-hash-based-signatures.xhtml#xmss-mt-signatures">IANA, XMSS: Extended Hash-Based Signatures</see></item>
/// </list>
/// NOTE: Some parameter sets are RFC only, some NIST only, and a few conform to both. All are defined by IANA.
/// </summary>
enum XmssMTOid
{
    XMSSMT_SHA2_20_2_256 = 0x00000001,
    XMSSMT_SHA2_20_4_256,
    XMSSMT_SHA2_40_2_256,
    XMSSMT_SHA2_40_4_256,
    XMSSMT_SHA2_40_8_256,
    XMSSMT_SHA2_60_3_256,
    XMSSMT_SHA2_60_6_256,
    XMSSMT_SHA2_60_12_256,
    XMSSMT_SHA2_20_2_512,
    XMSSMT_SHA2_20_4_512,
    XMSSMT_SHA2_40_2_512,
    XMSSMT_SHA2_40_4_512,
    XMSSMT_SHA2_40_8_512,
    XMSSMT_SHA2_60_3_512,
    XMSSMT_SHA2_60_6_512,
    XMSSMT_SHA2_60_12_512,
    XMSSMT_SHAKE_20_2_256,
    XMSSMT_SHAKE_20_4_256,
    XMSSMT_SHAKE_40_2_256,
    XMSSMT_SHAKE_40_4_256,
    XMSSMT_SHAKE_40_8_256,
    XMSSMT_SHAKE_60_3_256,
    XMSSMT_SHAKE_60_6_256,
    XMSSMT_SHAKE_60_12_256,
    XMSSMT_SHAKE_20_2_512,
    XMSSMT_SHAKE_20_4_512,
    XMSSMT_SHAKE_40_2_512,
    XMSSMT_SHAKE_40_4_512,
    XMSSMT_SHAKE_40_8_512,
    XMSSMT_SHAKE_60_3_512,
    XMSSMT_SHAKE_60_6_512,
    XMSSMT_SHAKE_60_12_512,
    XMSSMT_SHA2_20_2_192,
    XMSSMT_SHA2_20_4_192,
    XMSSMT_SHA2_40_2_192,
    XMSSMT_SHA2_40_4_192,
    XMSSMT_SHA2_40_8_192,
    XMSSMT_SHA2_60_3_192,
    XMSSMT_SHA2_60_6_192,
    XMSSMT_SHA2_60_12_192,
    XMSSMT_SHAKE256_20_2_256,
    XMSSMT_SHAKE256_20_4_256,
    XMSSMT_SHAKE256_40_2_256,
    XMSSMT_SHAKE256_40_4_256,
    XMSSMT_SHAKE256_40_8_256,
    XMSSMT_SHAKE256_60_3_256,
    XMSSMT_SHAKE256_60_6_256,
    XMSSMT_SHAKE256_60_12_256,
    XMSSMT_SHAKE256_20_2_192,
    XMSSMT_SHAKE256_20_4_192,
    XMSSMT_SHAKE256_40_2_192,
    XMSSMT_SHAKE256_40_4_192,
    XMSSMT_SHAKE256_40_8_192,
    XMSSMT_SHAKE256_60_3_192,
    XMSSMT_SHAKE256_60_6_192,
    XMSSMT_SHAKE256_60_12_192,
}
