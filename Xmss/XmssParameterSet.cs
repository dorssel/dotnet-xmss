// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography;

#pragma warning disable CA1027 // Mark enums with FlagsAttribute (false positive)
public enum XmssParameterSet
#pragma warning restore CA1027 // Mark enums with FlagsAttribute
{
    None = 0,
#pragma warning disable CA1707 // Identifiers should not contain underscores
    XMSS_SHA2_10_256 = XmssParameterSetOID.XMSS_PARAM_SHA2_10_256,
    XMSS_SHA2_16_256 = XmssParameterSetOID.XMSS_PARAM_SHA2_16_256,
    XMSS_SHA2_20_256 = XmssParameterSetOID.XMSS_PARAM_SHA2_20_256,
    XMSS_SHAKE256_10_256 = XmssParameterSetOID.XMSS_PARAM_SHAKE256_10_256,
    XMSS_SHAKE256_16_256 = XmssParameterSetOID.XMSS_PARAM_SHAKE256_16_256,
    XMSS_SHAKE256_20_256 = XmssParameterSetOID.XMSS_PARAM_SHAKE256_20_256,
#pragma warning restore CA1707 // Identifiers should not contain underscores
}
