﻿// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace InternalUnitTests;

[TestClass]
sealed unsafe class ErrorStringMarshallerTests
{
    [TestMethod]
    public void ConvertToUnmanagedThrows()
    {
        _ = Assert.ThrowsException<NotImplementedException>(() =>
        {
            _ = ErrorStringMarshaller.ConvertToUnmanaged(string.Empty);
        });
    }

    [TestMethod]
    public void ConvertToManagedNull()
    {
        Assert.IsNull(ErrorStringMarshaller.ConvertToManaged(null));
    }

    [TestMethod]
    public void ConvertToManagedString()
    {
        fixed (byte* unmanaged = "test"u8)
        {
            Assert.AreEqual("test", ErrorStringMarshaller.ConvertToManaged(unmanaged));
        }
    }

    [TestMethod]
    public void FreeNullIsNoop()
    {
        ErrorStringMarshaller.Free(null);
    }

    [TestMethod]
    public void FreeIsNoop()
    {
        byte b;
        ErrorStringMarshaller.Free(&b);
    }
}
