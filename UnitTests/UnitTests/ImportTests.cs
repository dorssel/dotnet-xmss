// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;
using static Dorssel.Security.Cryptography.X509Certificates.XmssCertificateExtensions;

namespace UnitTests;

[TestClass]
sealed class ImportTests
{
#if false
    [TestMethod]
    public void ImportSubjectPublicKeyInfo()
    {
        using var xmss = new Xmss();
        xmss.ImportSubjectPublicKeyInfo(IetfExampleCertificate.SubjectPublicKeyInfo.Span, out _);

        Assert.IsTrue(xmss.HasPublicKey);
    }
#endif

    [TestMethod]
    public void ImportCertificatePublicKey()
    {
        using var xmss = new Xmss();
        xmss.ImportCertificatePublicKey(IetfExampleCertificate.Certificate);

        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportCertificatePublicKey_2()
    {
        using var xmss = new Xmss();
        xmss.ImportCertificatePublicKey(IetfExampleCertificate.Certificate2);

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
        xmss.ImportFromPem(asnPem);
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
        xmss.ImportFromPem(spkiPem);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void ImportFromPem_Certificate()
    {
        using var xmss = new Xmss();
        xmss.ImportFromPem(IetfExampleCertificate.Pem);
        Assert.IsTrue(xmss.HasPublicKey);
    }
}
