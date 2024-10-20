// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography.Xmss.Native;

public static partial class ExampleManagedWrappers
{
    public static XmssError VerificationInit(out XmssVerificationContext context, in XmssPublicKey publicKey, uint[] signature)
    {
        ArgumentNullException.ThrowIfNull(signature);
        unsafe
        {
            fixed (uint* ptr = signature)
            {
                return UnsafeNativeMethods.xmss_verification_init(out context, in publicKey, in *(XmssSignature*)ptr,
                    (nuint)(signature.Length * sizeof(uint)));
            }
        }
    }

    public static XmssError VerificationUpdate(ref XmssVerificationContext context, ReadOnlySpan<byte> part)
    {
        unsafe
        {
            fixed (byte* ptr = part)
            {
                var result = UnsafeNativeMethods.xmss_verification_update(ref context, ptr, (nuint)part.Length, out var part_verify);
                if (result == XmssError.XMSS_OKAY && part_verify != ptr)
                {
                    result = XmssError.XMSS_ERR_FAULT_DETECTED;
                }
                return result;
            }
        }
    }

    public static XmssError VerificationCheck(ref XmssVerificationContext context, in XmssPublicKey publicKey)
    {
        return UnsafeNativeMethods.xmss_verification_check(ref context, in publicKey);
    }
}
