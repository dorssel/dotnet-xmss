// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;
using NativeHelper;

namespace UnitTests;

[TestClass]
sealed class NativeHelperTests
{
    [AssemblyInitialize]
    public static void AssemblyInitialize(TestContext testContext)
    {
        _ = testContext;
        NativeLoader.Setup(Assembly.GetExecutingAssembly());
    }

    [TestMethod]
    public void LoadUnknownLibraryFails()
    {
        Assert.ThrowsException<DllNotFoundException>(() =>
        {
            _ = NativeMethods.unknown_library();
        });
    }
}
