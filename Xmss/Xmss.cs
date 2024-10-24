// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography;

public class Xmss : AsymmetricAlgorithm
{
    public static Version NativeHeadersVersion
    {
        get
        {
            return new(Defines.XMSS_LIBRARY_VERSION_MAJOR, Defines.XMSS_LIBRARY_VERSION_MINOR,
                Defines.XMSS_LIBRARY_VERSION_PATCH);
        }
    }

    public static Version NativeLibraryVersion
    {
        get
        {
            var nativeVersion = SafeNativeMethods.xmss_library_get_version();
            return new(Defines.XMSS_LIBRARY_GET_VERSION_MAJOR(nativeVersion),
                Defines.XMSS_LIBRARY_GET_VERSION_MINOR(nativeVersion), Defines.XMSS_LIBRARY_GET_VERSION_PATCH(nativeVersion));
        }
    }
}
