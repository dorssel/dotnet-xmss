// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class ImportTests
{
    [TestMethod]
    public void ImportPrivateKey()
    {
        var stateManager = new MemoryStateManager();

        {
            using var tmpXmss = new Xmss();
            tmpXmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportPrivateKey(stateManager);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);
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
#pragma warning disable CS0618 // Type or member is obsolete
            spkiPem = tmpXmss.ExportSubjectPublicKeyInfoPem();
#pragma warning restore CS0618 // Type or member is obsolete
        }

        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.ImportFromPem(spkiPem);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);
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
}
