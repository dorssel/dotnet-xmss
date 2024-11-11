// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography;

public class XmssException
    : CryptographicException
{
    public XmssException()
    {
    }

    public XmssException(string message) : base(message)
    {
    }

    public XmssException(string message, Exception innerException) : base(message, innerException)
    {
    }

    internal static void ThrowIfNotOkay(XmssError error)
    {
        switch (error)
        {
            case XmssError.XMSS_OKAY:
                return;
            default:
                throw new XmssException(UnsafeNativeMethods.xmss_error_to_description(error));
        }
    }
}
