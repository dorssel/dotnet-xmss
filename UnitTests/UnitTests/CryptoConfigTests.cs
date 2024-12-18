// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class CryptoConfigTests
{
    [TestMethod]
    public void Create()
    {
        using var xmss = Xmss.Create();

        Assert.IsNotNull(xmss);
    }

    [TestMethod]
    [RequiresUnreferencedCode("Calls Dorssel.Security.Cryptography.Xmss.Create(String)")]
    public void Create_Name()
    {
        Assert.IsNotNull(Xmss.IdAlgXmssHashsig.FriendlyName);
        Assert.AreEqual("xmss", Xmss.IdAlgXmssHashsig.FriendlyName);

#pragma warning disable CS0618 // Type or member is obsolete
        using var xmss = Xmss.Create("xmss");
#pragma warning restore CS0618 // Type or member is obsolete

        Assert.IsNotNull(xmss);
    }

    [TestMethod]
    public void RegisterWithCryptoConfig()
    {
        Xmss.RegisterWithCryptoConfig();

        Assert.AreEqual(Xmss.IdAlgXmssHashsig.Value, CryptoConfig.MapNameToOID("xmss"));
    }

    [TestMethod]
    public void RegisterWithCryptoConfig_Twice()
    {
        Xmss.RegisterWithCryptoConfig();
        Xmss.RegisterWithCryptoConfig();

        Assert.AreEqual(Xmss.IdAlgXmssHashsig.Value, CryptoConfig.MapNameToOID("xmss"));
    }

    [TestMethod]
    [DataRow(XmssParameterSet.XMSS_SHA2_10_256)]
    [DataRow(XmssParameterSet.XMSS_SHA2_16_256)]
    [DataRow(XmssParameterSet.XMSS_SHA2_20_256)]
    [DataRow(XmssParameterSet.XMSS_SHAKE256_10_256)]
    [DataRow(XmssParameterSet.XMSS_SHAKE256_16_256)]
    [DataRow(XmssParameterSet.XMSS_SHAKE256_20_256)]
    public void SignatureAlgorithm(XmssParameterSet parameterSet)
    {
        using var xmss = new Xmss();
        xmss.GeneratePrivateKey(new MemoryStateManager(), parameterSet, false);

        Assert.IsFalse(string.IsNullOrEmpty(xmss.SignatureAlgorithm));
    }

    [TestMethod]
    public void SignatureAlgorithm_Invalid()
    {
        using var xmss = new Xmss();

        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            _ = xmss.SignatureAlgorithm;
        });
    }
}
