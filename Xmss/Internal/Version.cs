// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Security;

namespace Dorssel.Security.Cryptography.Internal;

static partial class Defines
{
    internal static uint XMSS_LIBRARY_VERSION_CONSTRUCT(byte major, byte minor, byte patch)
    {
        return (((uint)major) << 16) | (((uint)minor) << 8) | patch;
    }

    internal static readonly uint XMSS_LIBRARY_VERSION = XMSS_LIBRARY_VERSION_CONSTRUCT(XMSS_LIBRARY_VERSION_MAJOR,
        XMSS_LIBRARY_VERSION_MINOR, XMSS_LIBRARY_VERSION_PATCH);
}

static partial class Defines
{
    internal static byte XMSS_LIBRARY_GET_VERSION_MAJOR(uint version)
    {
        return unchecked((byte)(version >> 16));
    }

    internal static byte XMSS_LIBRARY_GET_VERSION_MINOR(uint version)
    {
        return unchecked((byte)(version >> 8));
    }

    internal static byte XMSS_LIBRARY_GET_VERSION_PATCH(uint version)
    {
        return unchecked((byte)version);
    }
}

[SuppressUnmanagedCodeSecurity]
static partial class SafeNativeMethods
{
    [LibraryImport("xmss")]

    internal static partial uint xmss_library_get_version();
}
