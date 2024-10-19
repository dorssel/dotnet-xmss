// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Security;

namespace Dorssel.Security.Cryptography.Xmss.Native;

public unsafe struct XmssSigningContext { }

public static partial class Defines
{
    public static unsafe readonly int XMSS_SIGNING_CONTEXT_SIZE = 4 + 4 + 4 + 4 + (4 * sizeof(delegate* unmanaged<void>));
}

[SuppressUnmanagedCodeSecurityAttribute]
public static unsafe partial class UnsafeNativeMethods
{
    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    public static unsafe partial void xmss_free_signing_context(XmssSigningContext* signing_context);
}

public unsafe struct XmssInternalCache { }

// TODO: XMSS_CACHE_ENTRY_COUNT

// TODO: XMSS_PUBLIC_KEY_GENERATION_CACHE_SIZE

public unsafe struct XmssKeyContext { }

// TODO: XMSS_PRIVATE_KEY_STATEFUL_PART_SIZE

// TODO: XMSS_PRIVATE_KEY_STATELESS_PART_SIZE

// TODO: XMSS_KEY_CONTEXT_SIZE

[SuppressUnmanagedCodeSecurityAttribute]
public static unsafe partial class UnsafeNativeMethods
{
    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    public static unsafe partial void xmss_free_key_context(XmssKeyContext* key_context);
}

public unsafe struct XmssKeyGenerationContext { }

// TODO: XMSS_KEY_GENERATION_CONTEXT_SIZE

[SuppressUnmanagedCodeSecurityAttribute]
public static unsafe partial class UnsafeNativeMethods
{
    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    public static unsafe partial void xmss_free_key_generation_context(XmssKeyGenerationContext* key_generation_context);
}
