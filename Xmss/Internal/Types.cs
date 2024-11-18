// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography.Internal;

enum XmssDistantValues : int
{
    XMSS_DISTANT_VALUE_0 = 0x00,
    XMSS_DISTANT_VALUE_1 = 0xD2,
    XMSS_DISTANT_VALUE_2 = 0x55,
    XMSS_DISTANT_VALUE_3 = 0x87,
    XMSS_DISTANT_VALUE_4 = 0x99,
    XMSS_DISTANT_VALUE_5 = 0x4B,
    XMSS_DISTANT_VALUE_6 = 0xCC,
    XMSS_DISTANT_VALUE_7 = 0x1E,
    XMSS_DISTANT_VALUE_8 = 0xE1,
    XMSS_DISTANT_VALUE_9 = 0x33,
    XMSS_DISTANT_VALUE_A = 0xB4,
    XMSS_DISTANT_VALUE_B = 0x66,
    XMSS_DISTANT_VALUE_C = 0x78,
    XMSS_DISTANT_VALUE_D = 0xAA,
    XMSS_DISTANT_VALUE_E = 0x2D,
    XMSS_DISTANT_VALUE_F = 0xFF,
}

enum XmssError : int
{
    XMSS_OKAY = XmssDistantValues.XMSS_DISTANT_VALUE_1,
    XMSS_ERR_NULL_POINTER = XmssDistantValues.XMSS_DISTANT_VALUE_2,
    XMSS_ERR_INVALID_SIGNATURE = XmssDistantValues.XMSS_DISTANT_VALUE_3,
    XMSS_ERR_ARGUMENT_MISMATCH = XmssDistantValues.XMSS_DISTANT_VALUE_4,
    XMSS_ERR_ALLOC_ERROR = XmssDistantValues.XMSS_DISTANT_VALUE_5,
    XMSS_ERR_INVALID_BLOB = XmssDistantValues.XMSS_DISTANT_VALUE_6,
    XMSS_ERR_BAD_CONTEXT = XmssDistantValues.XMSS_DISTANT_VALUE_7,
    XMSS_ERR_INVALID_ARGUMENT = XmssDistantValues.XMSS_DISTANT_VALUE_8,
    XMSS_ERR_PARTITION_DONE = XmssDistantValues.XMSS_DISTANT_VALUE_9,
    XMSS_ERR_UNFINISHED_PARTITIONS = XmssDistantValues.XMSS_DISTANT_VALUE_A,
    XMSS_ERR_TOO_FEW_SIGNATURES_AVAILABLE = XmssDistantValues.XMSS_DISTANT_VALUE_B,
    XMSS_ERR_PARTITIONS_NOT_CONSECUTIVE = XmssDistantValues.XMSS_DISTANT_VALUE_C,
    XMSS_ERR_NO_PUBLIC_KEY = XmssDistantValues.XMSS_DISTANT_VALUE_D,
    XMSS_ERR_FAULT_DETECTED = XmssDistantValues.XMSS_DISTANT_VALUE_E,
    XMSS_UNINITIALIZED = XmssDistantValues.XMSS_DISTANT_VALUE_F
}

enum XmssParameterSetOID : int
{
    XMSS_PARAM_SHA2_10_256 = 1,
    XMSS_PARAM_SHA2_16_256 = 2,
    XMSS_PARAM_SHA2_20_256 = 3,
    XMSS_PARAM_SHAKE256_10_256 = 0x10,
    XMSS_PARAM_SHAKE256_16_256 = 0x11,
    XMSS_PARAM_SHAKE256_20_256 = 0x12,
}

static partial class Defines
{
    internal static byte XMSS_TREE_DEPTH(XmssParameterSetOID oid)
    {
        return oid switch
        {
            XmssParameterSetOID.XMSS_PARAM_SHA2_10_256 or XmssParameterSetOID.XMSS_PARAM_SHAKE256_10_256 => 10,
            XmssParameterSetOID.XMSS_PARAM_SHA2_16_256 or XmssParameterSetOID.XMSS_PARAM_SHAKE256_16_256 => 16,
            XmssParameterSetOID.XMSS_PARAM_SHA2_20_256 or XmssParameterSetOID.XMSS_PARAM_SHAKE256_20_256 => 20,
            _ => 0,
        };
    }
}

enum XmssIndexObfuscationSetting : int
{
    XMSS_INDEX_OBFUSCATION_OFF = XmssDistantValues.XMSS_DISTANT_VALUE_1,
    XMSS_INDEX_OBFUSCATION_ON = XmssDistantValues.XMSS_DISTANT_VALUE_2
}

enum XmssCacheType : int
{
    XMSS_CACHE_NONE = XmssDistantValues.XMSS_DISTANT_VALUE_1,
    XMSS_CACHE_SINGLE_LEVEL = XmssDistantValues.XMSS_DISTANT_VALUE_2,
    XMSS_CACHE_TOP = XmssDistantValues.XMSS_DISTANT_VALUE_3
}

unsafe struct XmssValue256
{
    internal fixed byte data[32];
}

static partial class Defines
{
    internal const int XMSS_VALUE_256_WORDS = 8;
}

unsafe struct XmssNativeValue256
{
    internal fixed uint data[Defines.XMSS_VALUE_256_WORDS];
}

unsafe struct XmssBuffer
{
    internal nuint data_size;
    internal byte* data;
}

unsafe delegate void* XmssReallocFunction(void* ptr, nuint size);

unsafe delegate void XmssFreeFunction(void* ptr);

unsafe delegate void XmssZeroizeFunction(void* ptr, nuint size);
