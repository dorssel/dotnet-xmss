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
            foreach (var libraryPath in Directory.EnumerateFiles(Path.Combine(baseDir, "runtimes"), "*", SearchOption.AllDirectories))
            {
                if (NativeLibrary.TryLoad(libraryPath, out nint handle))
                {
                    return handle;
                }
            }
            return 0;
        });
    }
}
