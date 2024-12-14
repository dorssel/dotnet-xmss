// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography.X509Certificates;

namespace Dorssel.Security.Cryptography.X509Certificates;

public static class XmssCertificateExtensions
{
    public static Xmss? GetXmssPublicKey(this X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        if (certificate.PublicKey.Oid.Value != Xmss.IdAlgXmssHashsig.Value)
        {
            return null;
        }
        var xmss = new Xmss();
        try
        {
            xmss.ImportCertificatePublicKey(certificate);
            var result = xmss;
            xmss = null;
            return result;
        }
        finally
        {
            xmss?.Dispose();
        }
    }
}
