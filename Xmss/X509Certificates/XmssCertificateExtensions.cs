// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dorssel.Security.Cryptography.X509Certificates;

/// <summary>
/// Provides an extension method for retrieving the XMSS implementation for the public key of an <see cref="X509Certificate2"/>.
/// </summary>
public static class XmssCertificateExtensions
{
    /// <summary>
    /// Gets the XMSS public key from the <see cref="X509Certificate2"/>.
    /// </summary>
    /// <param name="certificate">The certificate.</param>
    /// <returns>The public key, or <see langword="null"/> if the certificate does not have an XMSS public key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is <see langword="null"/>.</exception>
    /// <exception cref="CryptographicException">The XMSS library reports an error.
    ///     See the <see cref="Exception.Message"/> property for more information.</exception>
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
