// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// The exception that is thrown when an error occurs during a cryptographic operation that requires state management.
/// </summary>
public class XmssStateManagerException
    : CryptographicException
{
    /// <summary>
    /// Initializes a new instance of the <see cref="XmssStateManagerException"/> class with default properties.
    /// </summary>
    public XmssStateManagerException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="XmssStateManagerException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    public XmssStateManagerException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="XmssStateManagerException"/> class with a specified error message
    /// and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="innerException">The exception that is the cause of the current exception.
    ///     If the <paramref name="innerException"/> parameter is not <see langword="null"/>,
    ///     the current exception is raised in a <see langword="catch"/> block that handles the inner exception.</param>
    public XmssStateManagerException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
