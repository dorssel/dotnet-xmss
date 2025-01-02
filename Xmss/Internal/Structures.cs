// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;

namespace Dorssel.Security.Cryptography.Internal;

struct XmssPrivateKeyStatelessBlob
{
    internal nuint data_size;
    internal unsafe byte* data // originally: uint8_t[]
    {
        get
        {
            fixed (XmssPrivateKeyStatelessBlob* ptr = &this)
            {
                return (byte*)(ptr + 1);
            }
        }
    }
}

static partial class Defines
{
    internal static readonly int XMSS_PRIVATE_KEY_STATELESS_BLOB_SIZE = Unsafe.SizeOf<XmssPrivateKeyStatelessBlob>()
        + Unsafe.SizeOf<XmssValue256>() + 4 + 4 + 4 + 4 + XMSS_PRIVATE_KEY_STATELESS_PART_SIZE;
}

struct XmssPrivateKeyStatefulBlob
{
    internal nuint data_size;
    internal unsafe byte* data // originally: uint8_t[]
    {
        get
        {
            fixed (XmssPrivateKeyStatefulBlob* ptr = &this)
            {
                return (byte*)(ptr + 1);
            }
        }
    }
}

static partial class Defines
{
    internal static readonly int XMSS_PRIVATE_KEY_STATEFUL_BLOB_SIZE = Unsafe.SizeOf<XmssPrivateKeyStatefulBlob>() + Unsafe.SizeOf<XmssValue256>()
        + 4 + 4 + 4 + 4 + Unsafe.SizeOf<XmssValue256>() + (2 * XMSS_PRIVATE_KEY_STATEFUL_PART_SIZE);
}

struct XmssPublicKeyInternalBlob
{
    internal nuint data_size;
    internal unsafe byte* data // originally: uint8_t[]
    {
        get
        {
            fixed (XmssPublicKeyInternalBlob* ptr = &this)
            {
                return (byte*)(ptr + 1);
            }
        }
    }
}

static partial class Defines
{
    internal static int XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE(XmssCacheType cache_type, byte cache_level, XmssParameterSetOID param_set)
    {
        return Unsafe.SizeOf<XmssPublicKeyInternalBlob>() + Unsafe.SizeOf<XmssValue256>() + 4 + 4 + Unsafe.SizeOf<XmssValue256>()
            + Unsafe.SizeOf<XmssValue256>() + 4 + 4 + 4 + 4 + (Unsafe.SizeOf<XmssValue256>() * XMSS_CACHE_ENTRY_COUNT(cache_type, cache_level, param_set));
    }
}

struct XmssPublicKey
{
    internal uint scheme_identifier; // big-endian
    internal XmssValue256 root;
    internal XmssValue256 seed;
};

static partial class Defines
{
    internal static readonly int XMSS_PUBLIC_KEY_SIZE = Unsafe.SizeOf<XmssPublicKey>();
}

struct XmssSignature
{
    internal uint leaf_index; // big-endian
    internal XmssValue256 random_bytes;
    internal unsafe fixed byte wots_signature[67 * 32]; // originally: XmssValue256[67]
    internal unsafe XmssValue256* authentication_path // originally: XmssValue256[]
    {
        get
        {
            fixed (XmssSignature* ptr = &this)
            {
                return (XmssValue256*)(ptr + 1);
            }
        }
    }
}

struct XmssSignatureBlob
{
    internal nuint data_size;
    internal unsafe byte* data // originally: uint8_t[]
    {
        get
        {
            fixed (XmssSignatureBlob* ptr = &this)
            {
                return (byte*)(ptr + 1);
            }
        }
    }
}

[SuppressUnmanagedCodeSecurity]
static partial class UnsafeNativeMethods
{
    // originally: a static inline function
    internal static unsafe XmssSignature* xmss_get_signature_struct(XmssSignatureBlob* signature)
    {
        return signature is null ? (XmssSignature*)null : (XmssSignature*)(signature + 1);
    }
}

static partial class Defines
{
    internal static int XMSS_SIGNATURE_SIZE(XmssParameterSetOID param_set)
    {
        return Unsafe.SizeOf<XmssSignature>() + (Unsafe.SizeOf<XmssValue256>() * XMSS_TREE_DEPTH(param_set));
    }

    internal static int XMSS_SIGNATURE_BLOB_SIZE(XmssParameterSetOID param_set)
    {
        return Unsafe.SizeOf<XmssSignatureBlob>() + XMSS_SIGNATURE_SIZE(param_set);
    }

    internal const int XMSS_VERIFICATION_CONTEXT_SIZE = 4 + 4 + 8 + 8 + 200 + 8 + 32;
}

[StructLayout(LayoutKind.Explicit)]
struct XmssVerificationContext
{
    [FieldOffset(0)]
    internal unsafe fixed byte data[Defines.XMSS_VERIFICATION_CONTEXT_SIZE];

    [FieldOffset(0)]
    internal ulong alignment;
}
