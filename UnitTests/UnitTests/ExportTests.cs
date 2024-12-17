// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;
using static Dorssel.Security.Cryptography.X509Certificates.XmssCertificateExtensions;

namespace UnitTests;

[TestClass]
sealed class ExportTests
{
    [TestMethod]
    public void ExportAsnPublicKey()
    {
        using var xmss = IetfExampleCertificate.Certificate2.GetXmssPublicKey()!;

        var asn = xmss.ExportAsnPublicKey();
    }

    [TestMethod]
    public void ExportAsnPublicKeyPem()
    {
        using var xmss = IetfExampleCertificate.Certificate2.GetXmssPublicKey()!;

#pragma warning disable CS0618 // Type or member is obsolete
        var asnPem = xmss.ExportAsnPublicKeyPem();
#pragma warning restore CS0618 // Type or member is obsolete
        Console.WriteLine(asnPem.Length);
    }

    [TestMethod]
    public void ExportSubjectPublicKeyInfo()
    {
        using var xmss = IetfExampleCertificate.Certificate2.GetXmssPublicKey()!;

        var spki = xmss.ExportSubjectPublicKeyInfo();
    }

    [TestMethod]
    public void ExportSubjectPublicKeyInfoPem()
    {
        using var xmss = IetfExampleCertificate.Certificate2.GetXmssPublicKey()!;

        var spkiPem = xmss.ExportSubjectPublicKeyInfoPem();
        Console.WriteLine(spkiPem.Length);
    }
}
