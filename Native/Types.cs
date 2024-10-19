// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography.Xmss.Native;

public enum XmssDistantValues : int
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

#pragma warning disable CA1008 // Enums should have zero value
public enum XmssError : int
#pragma warning restore CA1008 // Enums should have zero value
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

#pragma warning disable CA1008 // Enums should have zero value
#pragma warning disable CA1027 // Mark enums with FlagsAttribute
public enum XmssParameterSetOID : int
#pragma warning restore CA1027 // Mark enums with FlagsAttribute
#pragma warning restore CA1008 // Enums should have zero value
{
    XMSS_PARAM_SHA2_10_256 = 1,
    XMSS_PARAM_SHA2_16_256 = 2,
    XMSS_PARAM_SHA2_20_256 = 3,
    XMSS_PARAM_SHAKE256_10_256 = 0x10,
    XMSS_PARAM_SHAKE256_16_256 = 0x11,
    XMSS_PARAM_SHAKE256_20_256 = 0x12,
}

// TODO: XMSS_TREE_DEPTH

#pragma warning disable CA1008 // Enums should have zero value
public enum XmssIndexObfuscationSetting : int
#pragma warning restore CA1008 // Enums should have zero value
{
    XMSS_INDEX_OBFUSCATION_OFF = XmssDistantValues.XMSS_DISTANT_VALUE_1,
    XMSS_INDEX_OBFUSCATION_ON = XmssDistantValues.XMSS_DISTANT_VALUE_2
}

#pragma warning disable CA1008 // Enums should have zero value
public enum XmssCacheType : int
#pragma warning restore CA1008 // Enums should have zero value
{
    XMSS_CACHE_NONE = XmssDistantValues.XMSS_DISTANT_VALUE_1,
    XMSS_CACHE_SINGLE_LEVEL = XmssDistantValues.XMSS_DISTANT_VALUE_2,
    XMSS_CACHE_TOP = XmssDistantValues.XMSS_DISTANT_VALUE_3
}

public unsafe struct XmssValue256
{
    public fixed byte data[32];
}

// TODO: XMSS_VALUE_256_WORDS

// TODO: XmssNativeValue256

public unsafe struct XmssBuffer
{
    public nuint data_size;
    public byte* data;
}

public unsafe delegate void* XmssReallocFunction(void* ptr, nuint size);

public unsafe delegate void XmssFreeFunction(void* ptr);

public unsafe delegate void XmssZeroizeFunction(void* ptr, nuint size);
