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

    internal XmssException(XmssError error) : base(UnsafeNativeMethods.xmss_error_to_description(error))
    {
    }

    internal static void ThrowIfNotOkay(XmssError error)
    {
        if (error == XmssError.XMSS_OKAY)
        {
            return;
        }
        throw new XmssException(error);
    }
}
