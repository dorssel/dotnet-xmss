// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace InternalUnitTests;

[TestClass]
sealed unsafe class OpaqueStructuresTests
{
    [TestMethod]
    public void XMSS_SIGNING_CONTEXT_SIZE()
    {
        _ = Defines.XMSS_SIGNING_CONTEXT_SIZE;
    }

    [TestMethod]
    public void XMSS_INTERNAL_CACHE_SIZE()
    {
        _ = Defines.XMSS_INTERNAL_CACHE_SIZE(XmssCacheType.XMSS_CACHE_NONE, 2, XmssParameterSetOID.XMSS_PARAM_SHA2_10_256);
        _ = Defines.XMSS_INTERNAL_CACHE_SIZE(XmssCacheType.XMSS_CACHE_SINGLE_LEVEL, 2, XmssParameterSetOID.XMSS_PARAM_SHA2_10_256);
        _ = Defines.XMSS_INTERNAL_CACHE_SIZE(XmssCacheType.XMSS_CACHE_TOP, 2, XmssParameterSetOID.XMSS_PARAM_SHA2_10_256);
        _ = Defines.XMSS_INTERNAL_CACHE_SIZE(XmssCacheType.XMSS_CACHE_TOP, byte.MaxValue, XmssParameterSetOID.XMSS_PARAM_SHA2_10_256);
        _ = Defines.XMSS_INTERNAL_CACHE_SIZE(0, 2, XmssParameterSetOID.XMSS_PARAM_SHA2_10_256);
    }

    [TestMethod]
    public void XMSS_PUBLIC_KEY_GENERATION_CACHE_SIZE()
    {
        _ = Defines.XMSS_PUBLIC_KEY_GENERATION_CACHE_SIZE(2);
    }

    [TestMethod]
    public void XMSS_KEY_CONTEXT_SIZE()
    {
        _ = Defines.XMSS_KEY_CONTEXT_SIZE(XmssParameterSetOID.XMSS_PARAM_SHA2_10_256, XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_OFF);
        _ = Defines.XMSS_KEY_CONTEXT_SIZE(XmssParameterSetOID.XMSS_PARAM_SHA2_10_256, XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_ON);
    }

    [TestMethod]
    public void XMSS_KEY_GENERATION_CONTEXT_SIZE()
    {
        _ = Defines.XMSS_KEY_GENERATION_CONTEXT_SIZE(2);
    }
}
