// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Security;

namespace Dorssel.Security.Cryptography.Internal;

[SuppressUnmanagedCodeSecurity]
static partial class UnsafeNativeMethods
{
    [LibraryImport("xmss", StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(ErrorStringMarshaller))]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static partial string xmss_error_to_name(XmssError error);

    [LibraryImport("xmss", StringMarshalling = StringMarshalling.Custom, StringMarshallingCustomType = typeof(ErrorStringMarshaller))]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static partial string xmss_error_to_description(XmssError error);
}
