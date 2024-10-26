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
    internal static unsafe partial XmssError xmss_context_initialize(ref XmssSigningContext* context, XmssParameterSetOID parameter_set,
        XmssReallocFunction custom_realloc, XmssFreeFunction custom_free, XmssZeroizeFunction zeroize);

    // TODO: xmss_load_private_key

    // TODO: xmss_load_public_key

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static unsafe partial XmssError xmss_generate_private_key(ref XmssKeyContext* key_context, ref XmssPrivateKeyStatelessBlob* private_key,
        ref XmssPrivateKeyStatefulBlob* key_usage, in XmssBuffer secure_random, XmssIndexObfuscationSetting index_obfuscation_setting, in XmssBuffer random,
        in XmssSigningContext context);

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static unsafe partial XmssError xmss_generate_public_key(ref XmssKeyGenerationContext* generation_buffer, ref XmssInternalCache* cache,
        ref XmssInternalCache* generation_cache, in XmssKeyContext key_context, XmssCacheType cache_type, byte cache_level, uint generation_partitions);

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static partial XmssError xmss_calculate_public_key_part(ref XmssKeyGenerationContext generation_buffer, uint partition_index);

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    public static unsafe partial XmssError xmss_finish_calculate_public_key(ref XmssPublicKeyInternalBlob* public_key,
        ref XmssKeyGenerationContext* generation_buffer, ref XmssKeyContext key_context);

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static unsafe partial XmssError xmss_request_future_signatures(ref XmssPrivateKeyStatefulBlob* new_key_usage, ref XmssKeyContext key_context,
        uint signature_count);

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static unsafe partial XmssError xmss_sign_message(ref XmssSignatureBlob* signature, ref XmssKeyContext key_context, in XmssBuffer message);

    // TODO: xmss_partition_signature_space

    // TODO: xmss_merge_signature_space

    // TODO: xmss_get_signature_count

    // TODO: xmss_verify_public_key

    // TODO: xmss_verify_private_key_stateless

    // TODO: xmss_verify_private_key_stateful

    // TODO: xmss_get_caching_in_public_key

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]
    internal static partial XmssError xmss_export_public_key(out XmssPublicKey exported_pub_key, in XmssKeyContext key_context);

    // TODO: xmss_verify_exported_public_key
}
