// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Security;

namespace Dorssel.Security.Cryptography.Xmss.Native;

public unsafe struct XmssPrivateKeyStatelessBlob
{
    public nuint data_size;
    public byte* data // originally: uint8_t[]
    {
        get
        {
            fixed (XmssPrivateKeyStatelessBlob* ptr = &this)
            {
                return (byte*)(&ptr + 1);
            }
        }
    }
}

// TODO: XMSS_PRIVATE_KEY_STATELESS_BLOB_SIZE

public unsafe struct XmssPrivateKeyStatefulBlob
{
    public nuint data_size;
    public byte* data // originally: uint8_t[]
    {
        get
        {
            fixed (XmssPrivateKeyStatefulBlob* ptr = &this)
            {
                return (byte*)(&ptr + 1);
            }
        }
    }
}

// TODO: XMSS_PRIVATE_KEY_STATEFUL_BLOB_SIZE

public unsafe struct XmssPublicKeyInternalBlob
{
    public nuint data_size;
    public byte* data // originally: uint8_t[]
    {
        get
        {
            fixed (XmssPublicKeyInternalBlob* ptr = &this)
            {
                return (byte*)(&ptr + 1);
            }
        }
    }
}

// TODO: XMSS_PUBLIC_KEY_INTERNAL_BLOB_SIZE

public struct XmssPublicKey
{
    public uint scheme_identifier; // big-endian
    public XmssValue256 root;
    public XmssValue256 seed;
};

public static partial class Defines
{
    public static readonly unsafe nuint XMSS_PUBLIC_KEY_SIZE = (nuint)sizeof(XmssPublicKey);
}

public unsafe struct XmssSignature
{
    public uint leaf_index; // big-endian
    public XmssValue256 random_bytes;
    public fixed byte wots_signature[67 * 32]; // originally: XmssValue256[32]
    public XmssValue256* authentication_path // originally: XmssValue256[]
    {
        get
        {
            fixed (XmssSignature* ptr = &this)
            {
                return (XmssValue256*)(&ptr + 1);
            }
        }
    }
}

public unsafe struct XmssSignatureBlob
{
    public nuint data_size;
    public byte* data // originally: uint8_t[]
    {
        get
        {
            fixed (XmssSignatureBlob* ptr = &this)
            {
                return (byte*)(&ptr + 1);
            }
        }
    }
}

[SuppressUnmanagedCodeSecurityAttribute]
public static unsafe partial class UnsafeNativeMethods
{
    // originally: a static inline function
    public static unsafe XmssSignature* xmss_get_signature_struct(XmssSignatureBlob* signature)
    {
        if (signature is null)
        {
            return null;
        }
        return (XmssSignature*)(signature + 1);
    }
}

// TODO: XMSS_SIGNATURE_SIZE

// TODO: XMSS_SIGNATURE_BLOB_SIZE

// TODO: XMSS_VERIFICATION_CONTEXT_SIZE

public static partial class Defines
{
    public const int XMSS_VERIFICATION_CONTEXT_SIZE = 4 + 4 + 8 + 8 + 200 + 8 + 32;
}

[StructLayout(LayoutKind.Explicit)]
public unsafe struct XmssVerificationContext
{
    [FieldOffset(0)]
    public fixed byte data[Defines.XMSS_VERIFICATION_CONTEXT_SIZE];

    [FieldOffset(0)]
    public ulong alignment;
}
