// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace Dorssel.Security.Cryptography.Internal;

[CustomMarshaller(typeof(string), MarshalMode.Default, typeof(ErrorStringMarshaller))]
static unsafe class ErrorStringMarshaller
{
    public static byte* ConvertToUnmanaged(string? managed) => throw new NotImplementedException();

    public static string? ConvertToManaged(byte* unmanaged) => Marshal.PtrToStringAnsi((nint)unmanaged);

    public static void Free(byte* unmanaged) => _ = unmanaged;
}
