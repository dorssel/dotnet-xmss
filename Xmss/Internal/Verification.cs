// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Security;

namespace Dorssel.Security.Cryptography.Internal;

[SuppressUnmanagedCodeSecurity]
static partial class UnsafeNativeMethods
{
    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static partial XmssError xmss_verification_init(out XmssVerificationContext context,
        in XmssPublicKey public_key, in XmssSignature signature, nuint signature_length);

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static unsafe partial XmssError xmss_verification_update(ref XmssVerificationContext context, byte* part, nuint part_length,
        out byte* part_verify);

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static partial XmssError xmss_verification_check(ref XmssVerificationContext context, in XmssPublicKey public_key);
}
