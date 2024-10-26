// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace UnitTests;

[TestClass]
sealed unsafe class InternalErrorsTests
{
    [TestMethod]
    public void xmss_error_to_name()
    {
        foreach (var error in Enum.GetValues<XmssError>())
        {
            Assert.AreEqual(error.ToString(), UnsafeNativeMethods.xmss_error_to_name(error));
        }
    }

    [TestMethod]
    public void xmss_error_to_description()
    {
        foreach (var error in Enum.GetValues<XmssError>())
        {
            Assert.IsFalse(string.IsNullOrEmpty(UnsafeNativeMethods.xmss_error_to_description(error)));
        }
    }
}
