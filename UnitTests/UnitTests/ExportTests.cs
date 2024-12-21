// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using static Dorssel.Security.Cryptography.X509Certificates.XmssCertificateExtensions;

namespace UnitTests;

[TestClass]
sealed class ExportTests
{
    [TestMethod]
    public void ExportRfcPublicKey()
    {
        using var xmss = ExampleCertificate.Certificate2.GetXmssPublicKey()!;

        var rfc = xmss.ExportRfcPublicKey();

        CollectionAssert.AreEqual(ExampleCertificate.Certificate2.PublicKey.EncodedKeyValue.RawData, rfc);
    }

    [TestMethod]
    public void TryExportRfcPublicKey_BufferTooShort()
    {
        using var xmss = ExampleCertificate.Certificate2.GetXmssPublicKey()!;

        Assert.IsFalse(xmss.TryExportRfcPublicKey(new byte[1], out var bytesWritten));
        Assert.AreEqual(0, bytesWritten);
    }

    [TestMethod]
    public void ExportAsnPublicKey()
    {
        using var xmss = ExampleCertificate.Certificate2.GetXmssPublicKey()!;

        var asn = xmss.ExportAsnPublicKey();
    }

    [TestMethod]
    public void TryExportAsnPublicKey_BufferTooShort()
    {
        using var xmss = ExampleCertificate.Certificate2.GetXmssPublicKey()!;

        Assert.IsFalse(xmss.TryExportAsnPublicKey(new byte[1], out var bytesWritten));
        Assert.AreEqual(0, bytesWritten);
    }

    [TestMethod]
    public void ExportAsnPublicKeyPem()
    {
        using var xmss = ExampleCertificate.Certificate2.GetXmssPublicKey()!;

#pragma warning disable CS0618 // Type or member is obsolete
        var asnPem = xmss.ExportAsnPublicKeyPem();
#pragma warning restore CS0618 // Type or member is obsolete
        Console.WriteLine(asnPem.Length);
    }

    [TestMethod]
    public void TryExportAsnPublicKeyPem_BufferTooShort()
    {
        using var xmss = ExampleCertificate.Certificate2.GetXmssPublicKey()!;

#pragma warning disable CS0618 // Type or member is obsolete
        Assert.IsFalse(xmss.TryExportAsnPublicKeyPem(new char[1], out var charsWritten));
#pragma warning restore CS0618 // Type or member is obsolete
        Assert.AreEqual(0, charsWritten);
    }

    [TestMethod]
    public void ExportSubjectPublicKeyInfo()
    {
        using var xmss = ExampleCertificate.Certificate2.GetXmssPublicKey()!;

        var info = xmss.ExportSubjectPublicKeyInfo();
    }

    [TestMethod]
    public void TryExportSubjectPublicKeyInfo_BufferTooShort()
    {
        using var xmss = ExampleCertificate.Certificate2.GetXmssPublicKey()!;

        Assert.IsFalse(xmss.TryExportSubjectPublicKeyInfo(new byte[1], out var bytesWritten));
        Assert.AreEqual(0, bytesWritten);
    }

    [TestMethod]
    public void ExportSubjectPublicKeyInfoPem()
    {
        using var xmss = ExampleCertificate.Certificate2.GetXmssPublicKey()!;

        var infoPem = xmss.ExportSubjectPublicKeyInfoPem();
        Console.WriteLine(infoPem.Length);
    }

    [TestMethod]
    public void TryExportSubjectPublicKeyInfoPem_BufferTooShort()
    {
        using var xmss = ExampleCertificate.Certificate2.GetXmssPublicKey()!;

        Assert.IsFalse(xmss.TryExportSubjectPublicKeyInfoPem(new char[1], out var charsWritten));
        Assert.AreEqual(0, charsWritten);
    }
}
