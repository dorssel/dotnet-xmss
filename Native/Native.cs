// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace Dorssel.Security.Cryptography.Xmss;

public static partial class Native
{
    public const int XMSS_VERIFICATION_CONTEXT_SIZE = 4 + 4 + 8 + 8 + 200 + 8 + 32;

    public unsafe struct XmssVerificationContext
    {
        public fixed ulong data[XMSS_VERIFICATION_CONTEXT_SIZE / sizeof(ulong)];
    };

    public unsafe struct XmssValue256
    {
        public fixed byte data[32];
    };

    public struct XmssPublicKey
    {
        public uint scheme_identifier;
        public XmssValue256 root;
        public XmssValue256 seed;
    };

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
    };

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
    };

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

    private static partial uint xmss_library_get_version();

    /// <summary>
    /// Bla.
    /// </summary>
    /// <returns>The library version.</returns>
    public static uint LibraryGetVersion()
    {
        return xmss_library_get_version();
    }

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.UseDllDirectoryForDependencies)]

    private static unsafe partial XmssError xmss_verification_init(out XmssVerificationContext context,
        in XmssPublicKey public_key, uint* signature, nuint signature_length);

    public static XmssError VerificationInit(out XmssVerificationContext context, in XmssPublicKey publicKey, uint[] signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        unsafe
        {
            fixed (uint* ptr = signature)
            {
                return xmss_verification_init(out context, in publicKey, ptr, (nuint)(signature.Length * sizeof(uint)));
            }
        }
    }

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.UseDllDirectoryForDependencies)]

    private static unsafe partial XmssError xmss_verification_update(ref XmssVerificationContext context,
        byte* part, nuint part_length, out byte* part_verify);

    public static XmssError VerificationUpdate(ref XmssVerificationContext context, ReadOnlySpan<byte> part)
    {
        unsafe
        {
            fixed (byte* ptr = part)
            {
                var result = xmss_verification_update(ref context, ptr, (nuint)part.Length, out var part_verify);
                if (result == XmssError.XMSS_OKAY && part_verify != ptr)
                {
                    result = XmssError.XMSS_ERR_FAULT_DETECTED;
                }
                return result;
            }
        }
    }

    [LibraryImport("xmss")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory)]

    private static partial XmssError xmss_verification_check(ref XmssVerificationContext context, in XmssPublicKey public_key);

    public static XmssError VerificationCheck(ref XmssVerificationContext context, in XmssPublicKey publicKey)
    {
        return xmss_verification_check(ref context, in publicKey);
    }
}
