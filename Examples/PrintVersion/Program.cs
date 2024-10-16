// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Xmss;

// This is only needed for software within this repository itself.
// When referencing the NuGet package this is not required.
NativeHelper.NativeLoader.Setup();

Console.WriteLine($"Library version: 0x{Native.LibraryGetVersion():X08}");
