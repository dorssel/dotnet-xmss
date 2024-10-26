// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Security;

namespace Dorssel.Security.Cryptography.Internal;

// TODO: XMSS_LIBRARY_VERSION_CONSTRUCT

// TODO: XMSS_LIBRARY_VERSION

static partial class Defines
{
    internal static byte XMSS_LIBRARY_GET_VERSION_MAJOR(uint version) => unchecked((byte)(version >> 16));

    internal static byte XMSS_LIBRARY_GET_VERSION_MINOR(uint version) => unchecked((byte)(version >> 8));

    internal static byte XMSS_LIBRARY_GET_VERSION_PATCH(uint version) => unchecked((byte)version);
}

[SuppressUnmanagedCodeSecurity]
static partial class SafeNativeMethods
{
    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]

    internal static partial uint xmss_library_get_version();
}
