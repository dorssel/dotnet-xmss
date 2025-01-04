// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography;

#pragma warning disable CA1027 // Mark enums with FlagsAttribute (false positive)
/// <summary>
/// The XMSS parameter sets that are supported by this library.
///
/// These are the supported subset of OIDs for XMSS parameter sets as defined in:
/// <list type="bullet">
/// <item>for SHA-256: <see href="https://datatracker.ietf.org/doc/html/rfc8391#section-5.3">RFC 8391, Section 5.3</see>
///     and <see href="https://doi.org/10.6028/NIST.SP.800-208">NIST SP 800-208</see>, Section 5.1.</item>
/// <item>for SHAKE256/256: <see href="https://doi.org/10.6028/NIST.SP.800-208">NIST SP 800-208</see>, Section 5.3.</item>
/// </list>
/// </summary>
public enum XmssParameterSet
#pragma warning restore CA1027 // Mark enums with FlagsAttribute
{
    /// <summary>
    /// Indicates that a specific parameter set has not been selected.
    /// </summary>
    None = 0,
#pragma warning disable CA1707 // Identifiers should not contain underscores (matches RFC & IANA registration)
    /// <summary>
    /// SHA-256, tree height 10.
    /// </summary>
    XMSS_SHA2_10_256 = XmssParameterSetOID.XMSS_PARAM_SHA2_10_256,
    /// <summary>
    /// SHA-256, tree height 16.
    /// </summary>
    XMSS_SHA2_16_256 = XmssParameterSetOID.XMSS_PARAM_SHA2_16_256,
    /// <summary>
    /// SHA-256, tree height 20.
    /// </summary>
    XMSS_SHA2_20_256 = XmssParameterSetOID.XMSS_PARAM_SHA2_20_256,
    /// <summary>
    /// SHAKE256/256, tree height 10.
    /// </summary>
    XMSS_SHAKE256_10_256 = XmssParameterSetOID.XMSS_PARAM_SHAKE256_10_256,
    /// <summary>
    /// SHAKE256/256, tree height 16.
    /// </summary>
    XMSS_SHAKE256_16_256 = XmssParameterSetOID.XMSS_PARAM_SHAKE256_16_256,
    /// <summary>
    /// SHAKE256/256, tree height 20.
    /// </summary>
    XMSS_SHAKE256_20_256 = XmssParameterSetOID.XMSS_PARAM_SHAKE256_20_256,
#pragma warning restore CA1707 // Identifiers should not contain underscores
}
