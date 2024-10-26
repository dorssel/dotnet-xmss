// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;
using System.Runtime.InteropServices;
using Dorssel.Security.Cryptography;

namespace NativeHelper;

public static class NativeLoader
{
    public static void Setup(Assembly? assembly = null)
    {
        NativeLibrary.SetDllImportResolver(assembly ?? typeof(Xmss).Assembly, (libraryName, assembly, searchPath) =>
        {
            if (libraryName != "xmss")
            {
                return 0;
            }
            var runtimes = Path.Combine(Path.GetDirectoryName(assembly.Location)!, "runtimes");
            if (!Directory.Exists(runtimes))
            {
                return 0;
            }
            foreach (var libraryPath in Directory.EnumerateFiles(runtimes, "*", SearchOption.AllDirectories))
            {
                if (NativeLibrary.TryLoad(libraryPath, out var handle))
                {
                    return handle;
                }
            }
            return 0;
        });
    }
}
