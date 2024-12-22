// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class XmssStateManagerExceptionTests
{
    [TestMethod]
    public void Constructor_Default()
    {
        _ = new XmssStateManagerException();
    }

    [TestMethod]
    public void Constructor_Message()
    {
        _ = new XmssStateManagerException("Some message.");
    }

    [TestMethod]
    public void Constructor_Message_Inner()
    {
        _ = new XmssStateManagerException("Some message.", new InvalidOperationException());
    }
}
