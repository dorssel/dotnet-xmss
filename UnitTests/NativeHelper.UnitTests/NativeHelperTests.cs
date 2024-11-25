// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;

namespace NativeHelper.UnitTests;

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
        _ = Assert.ThrowsException<DllNotFoundException>(() =>
        {
            _ = NativeMethods.unknown_library();
        });
    }
}
