// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.InteropServices;

namespace Internal.UnitTests.InteropServices;

[TestClass]
sealed class CriticalXmssPublicKeyInternalBlobHandleTests
{
    [TestMethod]
    public void Alloc()
    {
        using var blob = CriticalXmssPublicKeyInternalBlobHandle.Alloc(
            Dorssel.Security.Cryptography.Internal.XmssCacheType.XMSS_CACHE_TOP, 0,
            Dorssel.Security.Cryptography.XmssParameterSet.XMSS_SHA2_10_256);
    }
}
