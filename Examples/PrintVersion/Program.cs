// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

static class Program
{
    static void Main()
    {
        // This is only needed for software within this repository itself.
        // When referencing the NuGet package this is not required.
        NativeHelper.NativeLoader.Setup();

        Console.WriteLine($"Native headers version: {Xmss.NativeHeadersVersion}");
        Console.WriteLine($"Native library version: {Xmss.NativeLibraryVersion}");
    }
}
