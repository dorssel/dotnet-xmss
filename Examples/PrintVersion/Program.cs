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
            xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_20_256, false);
        }
#endif
        {
            using var stateManager = new XmssFileStateManager(@"C:\test");
            using var xmss = new Xmss();
            var progressLock = new object();
            var lastProgress = 0;
            xmss.ImportPrivateKey(stateManager);
            if (xmss.RequiresPublicKeyGeneration)
            {
                xmss.GeneratePublicKeyAsync(new Progress<double>(progress =>
                {
                    var intProgress = (int)progress;
                    lock(progressLock)
                    {
                        if (intProgress > lastProgress)
                        {
                            lastProgress = intProgress;
                            Console.Write($"\r{intProgress,3}");
                        }
                    }
                }), CancellationToken.None).Wait();
            }
            _ = xmss.Sign([1, 2, 3]);
        }
    }
}
