// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

/// <summary>
/// TODO
/// </summary>
public class XmssStateManagerException
    : IOException
{
    /// <summary>
    /// TODO
    /// </summary>
    public XmssStateManagerException()
    {
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="message">TODO</param>
    public XmssStateManagerException(string message) : base(message)
    {
    }

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="message">TODO</param>
    /// <param name="innerException">TODO</param>
    public XmssStateManagerException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
