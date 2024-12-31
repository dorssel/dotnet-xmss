// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Security;

namespace Dorssel.Security.Cryptography.Internal;

struct XmssSigningContext { }

static partial class Defines
{
    internal static readonly unsafe int XMSS_SIGNING_CONTEXT_SIZE = 4 + 4 + 4 + 4 + (4 * sizeof(delegate* unmanaged<void>));
}

[SuppressUnmanagedCodeSecurity]
static partial class UnsafeNativeMethods
{
    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static unsafe partial void xmss_free_signing_context(XmssSigningContext* signing_context);
}

struct XmssInternalCache { }

static partial class Defines
{
    internal static int XMSS_CACHE_ENTRY_COUNT(XmssCacheType cache_type, byte cache_level, XmssParameterSetOID param_set)
    {
        return cache_type == XmssCacheType.XMSS_CACHE_NONE ? 0 :
            (cache_level >= XMSS_TREE_DEPTH(param_set) ? 0 :
                (cache_type == XmssCacheType.XMSS_CACHE_SINGLE_LEVEL ? (1 << (XMSS_TREE_DEPTH(param_set) - cache_level)) :
                    (cache_type == XmssCacheType.XMSS_CACHE_TOP ? ((1 << (XMSS_TREE_DEPTH(param_set) - cache_level + 1)) - 1) :
                        0 /* Garbage in, 0 out. */
                    )
                )
            )
        ;
    }

    internal static unsafe int XMSS_INTERNAL_CACHE_SIZE(XmssCacheType cache_type, byte cache_level, XmssParameterSetOID param_set)
    {
        return 4 + 4 + (sizeof(XmssValue256) * XMSS_CACHE_ENTRY_COUNT(cache_type, cache_level, param_set));
    }

    internal static unsafe int XMSS_PUBLIC_KEY_GENERATION_CACHE_SIZE(int number_of_partitions)
    {
        return 4 + 4 + (sizeof(XmssValue256) * number_of_partitions);
    }
}

struct XmssKeyContext { }

static partial class Defines
{
    internal const int XMSS_PRIVATE_KEY_STATEFUL_PART_SIZE = 4 + 4;

    internal static readonly unsafe int XMSS_PRIVATE_KEY_STATELESS_PART_SIZE = 32 + 32 + 4 + 4 + 32 + sizeof(XmssValue256) + 32;

    internal static unsafe int XMSS_KEY_CONTEXT_SIZE(XmssParameterSetOID param_set, XmssIndexObfuscationSetting obfuscation_setting)
    {
        return 4 + 4 + XMSS_SIGNING_CONTEXT_SIZE + XMSS_PRIVATE_KEY_STATELESS_PART_SIZE + (2 * XMSS_PRIVATE_KEY_STATEFUL_PART_SIZE)
        + ((3 * sizeof(XmssValue256)) + sizeof(void*) + 4 + 4)
        + (4 * (1 << XMSS_TREE_DEPTH(param_set)) * ((obfuscation_setting == XmssIndexObfuscationSetting.XMSS_INDEX_OBFUSCATION_ON) ? 1 : 0));
    }
}

[SuppressUnmanagedCodeSecurity]
static partial class UnsafeNativeMethods
{
    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static unsafe partial void xmss_free_key_context(XmssKeyContext* key_context);
}

struct XmssKeyGenerationContext { }

static partial class Defines
{
    internal static unsafe int XMSS_KEY_GENERATION_CONTEXT_SIZE(int generation_partitions)
    {
        return sizeof(void*) + sizeof(uint) + sizeof(uint) + sizeof(void*) + sizeof(void*) + (sizeof(uint) * generation_partitions);
    }
}

[SuppressUnmanagedCodeSecurity]
static partial class UnsafeNativeMethods
{
    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static unsafe partial void xmss_free_key_generation_context(XmssKeyGenerationContext* key_generation_context);
}
