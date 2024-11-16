// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;

namespace NativeHelperUnitTests;

[TestClass]
sealed class NoRuntimesTests
{
    [TestInitialize]
    public void TestInitialize()
    {
        // Ensure that the runtime for this platform does not exist.
        var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        Directory.Move(Path.Combine(baseDir, "runtimes"), Path.Combine(baseDir, "runtimes-moved"));
        _ = Directory.CreateDirectory(Path.Combine(baseDir, "runtimes"));
        File.Create(Path.Combine(baseDir, "runtimes", "xmss.so")).Close();
        File.Create(Path.Combine(baseDir, "runtimes", "xmss.dll")).Close();
    }

    [TestCleanup]
    public void TestCleanup()
    {
        var baseDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        Directory.Delete(Path.Combine(baseDir, "runtimes"), true);
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
