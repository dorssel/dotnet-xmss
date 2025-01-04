// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;

namespace Internal.UnitTests;

[TestClass]
sealed class XmssExceptionTests
{
    [TestMethod]
    public void Constructor_Default()
    {
        _ = new XmssException();
    }

    [TestMethod]
    public void Constructor_Message()
    {
        _ = new XmssException("Some message.");
    }

    [TestMethod]
    public void Constructor_Message_Inner()
    {
        _ = new XmssException("Some message.", new InvalidOperationException());
    }

    [TestMethod]
    public void Constructor_Error_Inner()
    {
        _ = new XmssException(XmssError.XMSS_ERR_FAULT_DETECTED, new InvalidOperationException());
    }

    [TestMethod]
    public void ThrowIfNotOkay_Error()
    {
        Assert.ThrowsException<XmssException>(() =>
        {
            XmssException.ThrowIfNotOkay(XmssError.XMSS_ERR_FAULT_DETECTED);
        });
    }

    [TestMethod]
    public void ThrowIfNotOkay_Okay()
    {
        XmssException.ThrowIfNotOkay(XmssError.XMSS_OKAY);
    }

    [TestMethod]
    public void ThrowFaultDetectedIf_False()
    {
        XmssException.ThrowFaultDetectedIf(false);
    }

    [TestMethod]
    public void ThrowFaultDetectedIf_True()
    {
        Assert.ThrowsException<XmssException>(() =>
        {
            XmssException.ThrowFaultDetectedIf(true);
        });
    }

    [TestMethod]
    public void ThrowFaultDetectedIf_Null()
    {
        XmssException.ThrowFaultDetectedIf(null);
    }

    [TestMethod]
    public void ThrowFaultDetectedIf_Exception()
    {
        var inner = new InvalidOperationException();

        var exception = Assert.ThrowsException<XmssException>(() =>
        {
            XmssException.ThrowFaultDetectedIf(inner);
        });
        Assert.AreEqual(inner, exception.InnerException);
    }
}
