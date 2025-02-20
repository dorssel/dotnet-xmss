// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dorssel.Security.Cryptography;
using static Dorssel.Security.Cryptography.X509Certificates.XmssCertificateExtensions;

namespace UnitTests;

[TestClass]
sealed class XmssCertificateExtensionsTests
{
    [TestMethod]
    public void GetXmssPublicKey()
    {
        using var xmss = ExampleCertificate.Certificate2.GetXmssPublicKey();

        Assert.IsNotNull(xmss);
        Assert.IsTrue(xmss.HasPublicKey);
    }

    [TestMethod]
    public void GetXmssPublicKey_WrongAlgorithm()
    {
        using var rsa = RSA.Create();
        var request = new CertificateRequest("CN=Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var now = DateTimeOffset.Now;
        using var rsaCertificate = request.CreateSelfSigned(now, now);

        using var xmss = rsaCertificate.GetXmssPublicKey();

        Assert.IsNull(xmss);
    }

    [TestMethod]
    public void GetXmssPublicKey_InvalidXmssKey()
    {
        var parameters = new AsnWriter(AsnEncodingRules.DER);
        {
            parameters.WriteNull();
        }
        var invalidXmssKey = new PublicKey(Xmss.IdAlgXmssHashsig, new(parameters.Encode()), new([42]));
        var request = new CertificateRequest(new X500DistinguishedName("CN=Test"), invalidXmssKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        using var rsa = RSA.Create();
        var now = DateTimeOffset.Now;
        using var rsaCertificate = request.Create(new("CN=TestIssuer"), X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pss), now, now, [1]);

        Assert.ThrowsExactly<CryptographicException>(() =>
        {
            using var xmss = rsaCertificate.GetXmssPublicKey();
        });
    }
}
