// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

class IgnoreException
    : CryptographicException
{
    public IgnoreException()
    {
    }

    public IgnoreException(string message) : base(message)
    {
    }

    public IgnoreException(string message, Exception innerException) : base(message, innerException)
    {
    }

    public IgnoreException(Exception innerException) : this("Ignored.", innerException)
    {
    }
}
