// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;

namespace NativeHelperUnitTests;

[TestClass]
sealed class NoRuntimeTests
{
    [TestInitialize]
    public void TestInitialize()
    {
        // Ensure that the runtimes directory does not exist at all.
        var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        Directory.Move(Path.Combine(baseDir, "runtimes"), Path.Combine(baseDir, "runtimes-moved"));
    }

    [TestCleanup]
    public void TestCleanup()
    {
        var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        Directory.Move(Path.Combine(baseDir, "runtimes-moved"), Path.Combine(baseDir, "runtimes"));
    }

    [TestMethod]
    public void LoadFails()
    {
        _ = Assert.ThrowsException<DllNotFoundException>(() =>
        {
            _ = NativeMethods.xmss_library_get_version();
        });
    }
}
