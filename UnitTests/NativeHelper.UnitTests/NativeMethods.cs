// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace NativeHelper.UnitTests;

static partial class NativeMethods
{
    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static partial uint xmss_library_get_version();

    [LibraryImport("unknown_library")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static partial uint unknown_library();
}
