// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;
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
        var stateManager = new MemoryStateManager();

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
        var stateManager1 = new MemoryStateManager();
        var stateManager2 = new MemoryStateManager();

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
    public void ImportRfcPublicKey()
    {
        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportRfcPublicKey(IetfExampleCertificate.PublicKey.EncodedKeyValue.RawData, out var bytesRead);

        Assert.AreEqual(IetfExampleCertificate.PublicKey.EncodedKeyValue.RawData.Length, bytesRead);
        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportRfcPublicKey_TooShort()
    {
        using var xmss = new Xmss();

        Assert.ThrowsException<CryptographicException>(() =>
        {
            xmss.ImportRfcPublicKey([1], out _);
        });
    }

    [TestMethod]
    public void ImportRfcPublicKey_WrongOid()
    {
        using var xmss = new Xmss();

        var wrong = new byte[IetfExampleCertificate.RfcPublicKey.Length];

        Assert.ThrowsException<CryptographicException>(() =>
        {
            xmss.ImportRfcPublicKey(wrong, out _);
        });
    }

    [TestMethod]
    public void ImportRfcPublicKey_WrongSize()
    {
        using var xmss = new Xmss();

        var tooShort = IetfExampleCertificate.RfcPublicKey[..^1];

        Assert.ThrowsException<CryptographicException>(() =>
        {
            xmss.ImportRfcPublicKey(tooShort.Span, out _);
        });
    }

    [TestMethod]
    public void ImportRfcPublicKey_AfterPrivateKey()
    {
        using var xmss = new Xmss();
        xmss.GeneratePrivateKey(new MemoryStateManager(), XmssParameterSet.XMSS_SHA2_10_256, false);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportRfcPublicKey(IetfExampleCertificate.PublicKey.EncodedKeyValue.RawData, out var bytesRead);

        Assert.AreEqual(IetfExampleCertificate.PublicKey.EncodedKeyValue.RawData.Length, bytesRead);
        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportAsnPublicKey()
    {
        byte[] asn;
        {
            using var tmpXmss = new Xmss();
            tmpXmss.ImportFromPem(IetfExampleCertificate.Pem);
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

        Assert.ThrowsException<CryptographicException>(() =>
        {
            xmss.ImportAsnPublicKey([42], out var bytesRead);
        });
    }

    [TestMethod]
    public void ImportSubjectPublicKeyInfo()
    {
        byte[] spki;
        {
            using var tmpXmss = new Xmss();
            tmpXmss.ImportFromPem(IetfExampleCertificate.Pem);
            spki = tmpXmss.ExportSubjectPublicKeyInfo();
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportSubjectPublicKeyInfo(spki, out var bytesRead);

        Assert.AreEqual(spki.Length, bytesRead);
        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportSubjectPublicKeyInfo_WrongOid()
    {
        byte[] spki;
        {
            using var rsa = RSA.Create();
            spki = rsa.ExportSubjectPublicKeyInfo();
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        Assert.ThrowsException<CryptographicException>(() =>
        {
            xmss.ImportSubjectPublicKeyInfo(spki, out var bytesRead);
        });
    }

    [TestMethod]
    public void ImportCertificatePublicKey()
    {
        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportCertificatePublicKey(IetfExampleCertificate.Certificate);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportCertificatePublicKey_2()
    {
        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportCertificatePublicKey(IetfExampleCertificate.Certificate2);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportFromPem_XmssAsn()
    {
        string asnPem;
        {
            using var tmpXmss = new Xmss();
            tmpXmss.ImportFromPem(IetfExampleCertificate.Pem);
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
        string spkiPem;
        {
            using var tmpXmss = new Xmss();
            tmpXmss.ImportFromPem(IetfExampleCertificate.Pem);
            spkiPem = tmpXmss.ExportSubjectPublicKeyInfoPem();
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportFromPem(spkiPem);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportFromPem_SubjectPublicKeyInfo_ExtraneousData()
    {
        string spkiPemWithExtraneousData;
        {
            using var tmpXmss = new Xmss();
            tmpXmss.ImportFromPem(IetfExampleCertificate.Pem);
            var spki = tmpXmss.ExportSubjectPublicKeyInfo();
            spkiPemWithExtraneousData = PemEncoding.WriteString("PUBLIC KEY", [.. spki, 42]);
        }

        using var xmss = new Xmss();

        Assert.ThrowsException<CryptographicException>(() =>
        {
            xmss.ImportFromPem(spkiPemWithExtraneousData);
        });
    }

    [TestMethod]
    public void ImportFromPem_Certificate()
    {
        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportFromPem(IetfExampleCertificate.Pem);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportFromPem_InvalidPem()
    {
        using var xmss = new Xmss();

        Assert.ThrowsException<ArgumentException>(() =>
        {
            xmss.ImportFromPem("This is invalid PEM.");
        });
    }

    [TestMethod]
    public void ImportFromPem_UnsupportedPem()
    {
        using var xmss = new Xmss();

        var unsupported = PemEncoding.WriteString("UNSUPPORTED", [1, 2, 3]);

        Assert.ThrowsException<ArgumentException>(() =>
        {
            xmss.ImportFromPem(unsupported);
        });
    }

    [TestMethod]
    public void ImportFromPem_AmbigousPem()
    {
        using var xmss = new Xmss();

        Assert.ThrowsException<ArgumentException>(() =>
        {
            xmss.ImportFromPem(IetfExampleCertificate.Pem + Environment.NewLine + IetfExampleCertificate.Pem);
        });
    }

    [TestMethod]
    public void ImportFromPem_PemNotFirst()
    {
        using var xmss = new Xmss();

        xmss.ImportFromPem(PemEncoding.WriteString("UNSUPPORTED", [1, 2, 3]) + Environment.NewLine + IetfExampleCertificate.Pem);
    }
}
