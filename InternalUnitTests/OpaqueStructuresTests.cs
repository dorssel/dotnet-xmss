// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace UnitTests;

[TestClass]
sealed unsafe class OpaqueStructuresTests
{
    [TestMethod]
    public void XMSS_SIGNING_CONTEXT_SIZE()
    {
        _ = Defines.XMSS_SIGNING_CONTEXT_SIZE;
    }
}
