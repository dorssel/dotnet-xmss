﻿// SPDX-FileCopyrightText: 2024 IETF Trust, D. Van Geest, K. Bashiri, S. Fluhrer, S. Gazdag, S. Kousidis
// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT
// SPDX-License-Identifier: LicenseRef-IETF-Trust

using System.Security.Cryptography.X509Certificates;
using Dorssel.Security.Cryptography;
using static Dorssel.Security.Cryptography.X509Certificates.XmssCertificateExtensions;

namespace UnitTests;

[TestClass]
sealed class PublicKey_KAT
{
    // See https://datatracker.ietf.org/doc/draft-ietf-lamps-x509-shbs/.
    // Licenced under LicenseRef-IETF-Trust
    const string IetfVector = """
        -----BEGIN CERTIFICATE-----
        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
        mQwlKdZfIrwGZ31n
        -----END CERTIFICATE-----
        """;

    [TestMethod]
    public void TestGetXmssPublicKey()
    {
        using var certificate = X509Certificate2.CreateFromPem(IetfVector);
        using var xmss = certificate.GetXmssPublicKey();
        Assert.IsNotNull(xmss);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void TestImportCertificate()
    {
        // NOTE: X509Certificate has been superseded by X509Certificate2, so we must use trickery to actually create one.
        using var certificate2 = X509Certificate2.CreateFromPem(IetfVector);
#pragma warning disable SYSLIB0057 // Type or member is obsolete
        using var certificate = new X509Certificate(certificate2.Export(X509ContentType.Cert));
#pragma warning restore SYSLIB0057 // Type or member is obsolete

        using var xmss = new Xmss();
        xmss.ImportCertificatePublicKey(certificate);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void TestImportCertificate2()
    {
        using var certificate = X509Certificate2.CreateFromPem(IetfVector);
        using var xmss = new Xmss();
        xmss.ImportCertificatePublicKey(certificate);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void TestImportAsnPem()
    {
        string asnPem;
        {
            using var tmpXmss = new Xmss();
            tmpXmss.ImportFromPem(IetfVector);
#pragma warning disable CS0618 // Type or member is obsolete
            asnPem = tmpXmss.ExportAsnPublicKeyPem();
#pragma warning restore CS0618 // Type or member is obsolete
        }

        using var xmss = new Xmss();
        xmss.ImportFromPem(asnPem);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void TestImportCertificatePem()
    {
        using var xmss = new Xmss();
        xmss.ImportFromPem(IetfVector);
        Assert.IsTrue(xmss.HasPublicKey);
    }
}
