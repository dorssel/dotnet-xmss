// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace UnitTests;

static class ExampleCertificate
{
    /// <summary>
    ///  See https://datatracker.ietf.org/doc/draft-ietf-lamps-x509-shbs/.
    /// </summary>
    public readonly static string Pem = File.ReadAllText("example_certificate.pem");

    public readonly static X509Certificate Certificate = new(X509CertificateLoader.LoadCertificate(Encoding.ASCII.GetBytes(Pem)));

    public readonly static X509Certificate2 Certificate2 = X509CertificateLoader.LoadCertificate(Encoding.ASCII.GetBytes(Pem));

    public readonly static PublicKey PublicKey = Certificate2.PublicKey;

    public readonly static ReadOnlyMemory<byte> RfcPublicKey = PublicKey.EncodedKeyValue.RawData;
}
