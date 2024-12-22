// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace Internal.UnitTests;

[TestClass]
sealed class IgnoreExceptionTests
{
    [TestMethod]
    public void Constructor_Default()
    {
        _ = new IgnoreException();
    }

    [TestMethod]
    public void Constructor_Message()
    {
        _ = new IgnoreException("Some message.");
    }

    [TestMethod]
    public void Constructor_Message_Inner()
    {
        _ = new IgnoreException("Some message.", new InvalidOperationException());
    }

    [TestMethod]
    public void Constructor_Inner()
    {
        _ = new IgnoreException(new InvalidOperationException());
    }
}
