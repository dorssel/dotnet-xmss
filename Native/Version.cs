// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Security;

namespace Dorssel.Security.Cryptography.Xmss;

[SuppressUnmanagedCodeSecurityAttribute]
public static unsafe partial class SafeNativeMethods
{
    // TODO: XMSS_LIBRARY_VERSION_MAJOR

    // TODO: XMSS_LIBRARY_VERSION_MINOR

    // TODO: XMSS_LIBRARY_VERSION_PATCH

    // TODO: XMSS_LIBRARY_VERSION_CONSTRUCT

    // TODO: XMSS_LIBRARY_VERSION

    // TODO: XMSS_LIBRARY_GET_VERSION_MAJOR

    // TODO: XMSS_LIBRARY_GET_VERSION_MINOR

    // TODO: XMSS_LIBRARY_GET_VERSION_PATCH

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

    public static partial uint xmss_library_get_version();
}
