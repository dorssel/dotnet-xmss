// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

static class Program
{
    static Program()
    {
        // This is only needed for software within this repository itself.
        // When referencing the NuGet package this is not required.
        NativeHelper.NativeLoader.Setup();
    }

    static void Main()
    {
        {
            using var xmss = new Xmss();
            Console.WriteLine($"Native headers version: {xmss.NativeHeadersVersion}");
            Console.WriteLine($"Native library version: {xmss.NativeLibraryVersion}");
        }
#if true
        {
            using var stateManager = new XmssFileStateManager(@"C:\test");
            stateManager.Delete();
            using var xmss = new Xmss();
            xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_16_256, false);
        }
#endif
        {
            using var stateManager = new XmssFileStateManager(@"C:\test");
            using var xmss = new Xmss();
            xmss.ImportPrivateKey(stateManager);
            if (xmss.RequiresPublicKeyGeneration)
            {
                xmss.GeneratePublicKeyAsync(progress => Console.Write($"\r{(int)progress,3}%")).Wait();
            }
            _ = xmss.Sign([1, 2, 3]);
        }
    }
}
