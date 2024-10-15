// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Xmss;
using System.Runtime.InteropServices;

namespace NativeHelper;

public static class NativeLoader
{
    public static void Setup()
    {
        NativeLibrary.SetDllImportResolver(typeof(Native).Assembly, (libraryName, assembly, searchPath) =>
        {
            if (libraryName != "xmss")
            {
                return 0;
            }
            if (Path.GetDirectoryName(assembly.Location) is not string baseDir)
            {
                return 0;
            }

            if (OperatingSystem.IsWindows() && Environment.Is64BitProcess)
            {
                return NativeLibrary.Load(Path.Combine(baseDir, "runtimes", "win-x64", "native", "xmss.dll"));
            }
            else if (OperatingSystem.IsLinux() && Environment.Is64BitProcess)
            {
                return NativeLibrary.Load(Path.Combine(baseDir, "runtimes", "linux-x64", "native", "xmss.so"));
            }
            else
            {
                return 0;
            }
        });
    }
}
