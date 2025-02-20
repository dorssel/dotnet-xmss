// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class ImportTests
{
    [TestMethod]
    [DataRow(XmssParameterSet.XMSS_SHA2_10_256)]
    [DataRow(XmssParameterSet.XMSS_SHA2_16_256)]
    [DataRow(XmssParameterSet.XMSS_SHA2_20_256)]
    [DataRow(XmssParameterSet.XMSS_SHAKE256_10_256)]
    [DataRow(XmssParameterSet.XMSS_SHAKE256_16_256)]
    [DataRow(XmssParameterSet.XMSS_SHAKE256_20_256)]
    public void ImportPrivateKey(XmssParameterSet parameterSet)
    {
        var stateManager = new MockStateManager();

        {
            using var tmpXmss = new Xmss();
            tmpXmss.GeneratePrivateKey(stateManager, parameterSet, false);
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportPrivateKey(stateManager);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);
        Assert.AreEqual(parameterSet, xmss.ParameterSet);
    }

    [TestMethod]
    public void ImportPrivateKey_AfterPrivateKey()
    {
        var stateManager1 = new MockStateManager();
        var stateManager2 = new MockStateManager();

        {
            using var tmpXmss = new Xmss();
            tmpXmss.GeneratePrivateKey(stateManager1, XmssParameterSet.XMSS_SHA2_10_256, false);
        }
        {
            using var tmpXmss = new Xmss();
            tmpXmss.GeneratePrivateKey(stateManager2, XmssParameterSet.XMSS_SHA2_16_256, false);
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportPrivateKey(stateManager1);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);
        Assert.AreEqual(XmssParameterSet.XMSS_SHA2_10_256, xmss.ParameterSet);

        xmss.ImportPrivateKey(stateManager2);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);
        Assert.AreEqual(XmssParameterSet.XMSS_SHA2_16_256, xmss.ParameterSet);
    }

    [TestMethod]
    public void ImportPrivateKey_Invalid()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        // corrupt blob such that not even the parameter set is valid
        Array.Clear(stateManager.GetPartData(XmssKeyPart.PrivateStateless)!);
        Array.Clear(stateManager.GetPartData(XmssKeyPart.PrivateStateful)!);

        Assert.ThrowsExactly<XmssException>(() =>
        {
            xmss.ImportPrivateKey(stateManager);
        });
    }

    [TestMethod]
    public void ImportRfcPublicKey()
    {
        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportRfcPublicKey(ExampleCertificate.PublicKey.EncodedKeyValue.RawData, out var bytesRead);

        Assert.AreEqual(ExampleCertificate.PublicKey.EncodedKeyValue.RawData.Length, bytesRead);
        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportRfcPublicKey_TooShort()
    {
        using var xmss = new Xmss();

        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            xmss.ImportRfcPublicKey([1], out _);
        });
    }

    [TestMethod]
    public void ImportRfcPublicKey_WrongOid()
    {
        using var xmss = new Xmss();

        var wrong = new byte[ExampleCertificate.RfcPublicKey.Length];

        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            xmss.ImportRfcPublicKey(wrong, out _);
        });
    }

    [TestMethod]
    public void ImportRfcPublicKey_WrongSize()
    {
        using var xmss = new Xmss();

        var tooShort = ExampleCertificate.RfcPublicKey[..^1];

        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            xmss.ImportRfcPublicKey(tooShort.Span, out _);
        });
    }

    [TestMethod]
    public void ImportRfcPublicKey_AfterPrivateKey()
    {
        using var xmss = new Xmss();
        xmss.GeneratePrivateKey(new MockStateManager(), XmssParameterSet.XMSS_SHA2_10_256, false);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportRfcPublicKey(ExampleCertificate.PublicKey.EncodedKeyValue.RawData, out var bytesRead);

        Assert.AreEqual(ExampleCertificate.PublicKey.EncodedKeyValue.RawData.Length, bytesRead);
        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportAsnPublicKey()
    {
        byte[] asn;
        {
            using var tmpXmss = new Xmss();
            tmpXmss.ImportFromPem(ExampleCertificate.Pem);
            asn = tmpXmss.ExportAsnPublicKey();
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportAsnPublicKey(asn, out var bytesRead);

        Assert.AreEqual(asn.Length, bytesRead);
        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportAsnPublicKey_Invalid()
    {
        using var xmss = new Xmss();

        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            xmss.ImportAsnPublicKey([42], out var bytesRead);
        });
    }

    [TestMethod]
    public void ImportSubjectPublicKeyInfo()
    {
        byte[] info;
        {
            using var tmpXmss = new Xmss();
            tmpXmss.ImportFromPem(ExampleCertificate.Pem);
            info = tmpXmss.ExportSubjectPublicKeyInfo();
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportSubjectPublicKeyInfo(info, out var bytesRead);

        Assert.AreEqual(info.Length, bytesRead);
        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportSubjectPublicKeyInfo_WrongOid()
    {
        byte[] info;
        {
            using var rsa = RSA.Create();
            info = rsa.ExportSubjectPublicKeyInfo();
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            xmss.ImportSubjectPublicKeyInfo(info, out var bytesRead);
        });
    }

    [TestMethod]
    public void ImportCertificatePublicKey()
    {
        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportCertificatePublicKey(ExampleCertificate.Certificate);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportCertificatePublicKey_2()
    {
        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportCertificatePublicKey(ExampleCertificate.Certificate2);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportFromPem_XmssAsn()
    {
        string asnPem;
        {
            using var tmpXmss = new Xmss();
            tmpXmss.ImportFromPem(ExampleCertificate.Pem);
#pragma warning disable CS0618 // Type or member is obsolete
            asnPem = tmpXmss.ExportAsnPublicKeyPem();
#pragma warning restore CS0618 // Type or member is obsolete
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportFromPem(asnPem);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportFromPem_SubjectPublicKeyInfo()
    {
        string infoPem;
        {
            using var tmpXmss = new Xmss();
            tmpXmss.ImportFromPem(ExampleCertificate.Pem);
            infoPem = tmpXmss.ExportSubjectPublicKeyInfoPem();
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportFromPem(infoPem);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportFromPem_SubjectPublicKeyInfo_ExtraneousData()
    {
        string infoPemWithExtraneousData;
        {
            using var tmpXmss = new Xmss();
            tmpXmss.ImportFromPem(ExampleCertificate.Pem);
            var info = tmpXmss.ExportSubjectPublicKeyInfo();
            infoPemWithExtraneousData = PemEncoding.WriteString("PUBLIC KEY", [.. info, 42]);
        }

        using var xmss = new Xmss();

        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            xmss.ImportFromPem(infoPemWithExtraneousData);
        });
    }

    [TestMethod]
    public void ImportFromPem_Certificate()
    {
        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportFromPem(ExampleCertificate.Pem);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportFromPem_InvalidPem()
    {
        using var xmss = new Xmss();

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            xmss.ImportFromPem("This is invalid PEM.");
        });
    }

    [TestMethod]
    public void ImportFromPem_UnsupportedPem()
    {
        using var xmss = new Xmss();

        var unsupported = PemEncoding.WriteString("UNSUPPORTED", [1, 2, 3]);

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            xmss.ImportFromPem(unsupported);
        });
    }

    [TestMethod]
    public void ImportFromPem_AmbiguousPem()
    {
        using var xmss = new Xmss();

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            xmss.ImportFromPem(ExampleCertificate.Pem + Environment.NewLine + ExampleCertificate.Pem);
        });
    }

    [TestMethod]
    public void ImportFromPem_PemNotFirst()
    {
        using var xmss = new Xmss();

        xmss.ImportFromPem(PemEncoding.WriteString("UNSUPPORTED", [1, 2, 3]) + Environment.NewLine + ExampleCertificate.Pem);
    }
}
