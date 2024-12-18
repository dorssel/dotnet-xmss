// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
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

    internal XmssException(XmssError error, Exception innerException) : base(UnsafeNativeMethods.xmss_error_to_description(error), innerException)
    {
    }

    [StackTraceHidden]
    internal static void ThrowIfNotOkay(XmssError error)
    {
        if (error != XmssError.XMSS_OKAY)
        {
            throw new XmssException(error);
        }
    }

    [StackTraceHidden]
    [ExcludeFromCodeCoverage(Justification = "Not testable, unless actual faults are injected.")]
    internal static void ThrowFaultDetectedIf([DoesNotReturnIf(true)] bool condition)
    {
        if (condition)
        {
            throw new XmssException(XmssError.XMSS_ERR_FAULT_DETECTED);
        }
    }

    [StackTraceHidden]
    [ExcludeFromCodeCoverage(Justification = "Not testable, unless actual faults are injected.")]
    internal static void ThrowFaultDetectedIf(Exception? exception)
    {
        if (exception is not null)
        {
            throw new XmssException(XmssError.XMSS_ERR_FAULT_DETECTED, exception);
        }
    }
}
