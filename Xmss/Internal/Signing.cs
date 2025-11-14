// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Security;

namespace Dorssel.Security.Cryptography.Internal;

[SuppressUnmanagedCodeSecurity]
static partial class UnsafeNativeMethods
{
    // WASM requires function pointers to be passed as nuint; it cannot handle any form of delegate (neither managed nor unmanaged).
    [LibraryImport("xmss")]
    private static unsafe partial XmssError xmss_context_initialize(ref XmssSigningContext* context, XmssParameterSetOID parameter_set,
        nuint custom_realloc, nuint custom_free, nuint zeroize);

    // This signature works fine for LibraryImport *except* for WASM.
    internal static unsafe XmssError xmss_context_initialize(ref XmssSigningContext* context, XmssParameterSetOID parameter_set,
        delegate* unmanaged<void*, nuint, void*> custom_realloc, delegate* unmanaged<void*, void> custom_free, delegate* unmanaged<void*, nuint, void> zeroize)
    {
        return xmss_context_initialize(ref context, parameter_set, (nuint)custom_realloc, (nuint)custom_free, (nuint)zeroize);
    }

    [LibraryImport("xmss")]
    internal static unsafe partial XmssError xmss_load_private_key(ref XmssKeyContext* key_context, in XmssPrivateKeyStatelessBlob private_key,
        in XmssPrivateKeyStatefulBlob key_usage, in XmssSigningContext context);

    [LibraryImport("xmss")]
    internal static unsafe partial XmssError xmss_load_public_key(ref XmssInternalCache* cache, ref XmssKeyContext key_context,
        in XmssPublicKeyInternalBlob public_key);

    [LibraryImport("xmss")]
    internal static unsafe partial XmssError xmss_generate_private_key(ref XmssKeyContext* key_context, ref XmssPrivateKeyStatelessBlob* private_key,
        ref XmssPrivateKeyStatefulBlob* key_usage, in XmssBuffer secure_random, XmssIndexObfuscationSetting index_obfuscation_setting, in XmssBuffer random,
        in XmssSigningContext context);

    [LibraryImport("xmss")]
    internal static unsafe partial XmssError xmss_generate_public_key(ref XmssKeyGenerationContext* generation_buffer, ref XmssInternalCache* cache,
        ref XmssInternalCache* generation_cache, in XmssKeyContext key_context, XmssCacheType cache_type, byte cache_level, uint generation_partitions);

    [LibraryImport("xmss")]
    internal static partial XmssError xmss_calculate_public_key_part(ref XmssKeyGenerationContext generation_buffer, uint partition_index);

    [LibraryImport("xmss")]
    public static unsafe partial XmssError xmss_finish_calculate_public_key(ref XmssPublicKeyInternalBlob* public_key,
        ref XmssKeyGenerationContext* generation_buffer, ref XmssKeyContext key_context);

    [LibraryImport("xmss")]
    internal static unsafe partial XmssError xmss_request_future_signatures(ref XmssPrivateKeyStatefulBlob* new_key_usage, ref XmssKeyContext key_context,
        uint signature_count);

    [LibraryImport("xmss")]
    internal static unsafe partial XmssError xmss_sign_message(ref XmssSignatureBlob* signature, ref XmssKeyContext key_context, in XmssBuffer message);

    [LibraryImport("xmss")]
    internal static unsafe partial XmssError xmss_partition_signature_space(ref XmssPrivateKeyStatefulBlob* new_partition,
        ref XmssPrivateKeyStatefulBlob* updated_current_partition, ref XmssKeyContext key_context, uint new_partition_size);

    [LibraryImport("xmss")]
    internal static unsafe partial XmssError xmss_merge_signature_space(ref XmssPrivateKeyStatefulBlob* new_key_usage, ref XmssKeyContext key_context,
        in XmssPrivateKeyStatefulBlob partition_extension);

    [LibraryImport("xmss")]
    internal static partial XmssError xmss_get_signature_count(out nuint total_count, out nuint remaining_count, in XmssKeyContext key_context);

    [LibraryImport("xmss")]
    internal static partial XmssError xmss_verify_public_key(in XmssPublicKeyInternalBlob pub_key,
        in XmssPrivateKeyStatelessBlob private_key, in XmssKeyContext key_context);

    [LibraryImport("xmss")]
    internal static partial XmssError xmss_verify_private_key_stateless(in XmssPrivateKeyStatelessBlob private_key, in XmssSigningContext context);

    [LibraryImport("xmss")]
    internal static partial XmssError xmss_verify_private_key_stateful(in XmssPrivateKeyStatefulBlob key_usage,
        in XmssPrivateKeyStatelessBlob private_key, in XmssKeyContext key_context, in XmssSigningContext signing_context);

    [LibraryImport("xmss")]
    internal static partial XmssError xmss_get_caching_in_public_key(out XmssCacheType cache_type, out uint cache_level,
        in XmssPublicKeyInternalBlob pub_key);

    [LibraryImport("xmss")]
    internal static partial XmssError xmss_export_public_key(out XmssPublicKey exported_pub_key, in XmssKeyContext key_context);

    [LibraryImport("xmss")]
    internal static partial XmssError xmss_verify_exported_public_key(in XmssPublicKey exported_pub_key, in XmssKeyContext key_context);
}
