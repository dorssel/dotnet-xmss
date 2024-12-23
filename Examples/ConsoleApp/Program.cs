// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using Dorssel.Security.Cryptography;

static class Program
{
    static Program()
    {
        // This is only needed for software within this repository itself.
        // When referencing the NuGet package this is not required.
        NativeHelper.NativeLoader.Setup();
    }

    static async Task Main()
    {
        {
            Console.WriteLine($"Native headers version: {Xmss.NativeHeadersVersion}");
            Console.WriteLine($"Native library version: {Xmss.NativeLibraryVersion}");
        }
        {
            Xmss.RegisterWithCryptoConfig();
#pragma warning disable IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code
            var alg = CryptoConfig.CreateFromName("XMSS");
#pragma warning restore IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code
            var oid = CryptoConfig.MapNameToOID("XMSS");
        }
        {
            Console.WriteLine("Generating new key...");

            var stateManager = new XmssFileStateManager(@"C:\test");
            stateManager.DeleteAll();
            using var xmss = new Xmss();
            xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);
            {
                // this is special for XMSS, a long-running (cancelable) process

                using var cancellationTokenSource = new CancellationTokenSource();
                Console.CancelKeyPress += (sender, args) =>
                {
                    cancellationTokenSource.Cancel();
                    args.Cancel = true;
                };

                var oldPercentage = 0;
                try
                {
                    await xmss.CalculatePublicKeyAsync(progress =>
                    {
                        if (oldPercentage < (int)progress)
                        {
                            oldPercentage = (int)progress;
                            Console.Write($"\r{(int)progress,3}%");
                        }
                    }, cancellationTokenSource.Token).ConfigureAwait(false);
                }
                catch (AggregateException ex) when (ex.GetBaseException() is OperationCanceledException)
                {
                    Console.WriteLine();
                    Console.WriteLine("Canceled");
                    return;
                }
            }
            Console.WriteLine();
            Console.WriteLine("Public Key:");
            Console.WriteLine(xmss.ExportSubjectPublicKeyInfoPem());
        }
        var message = new byte[] { 1, 2, 3 };
        byte[] signature;
        string publicKeyPem;
        {
            Console.WriteLine("Signing a message...");

            using var xmss = new Xmss();
            xmss.ImportPrivateKey(new XmssFileStateManager(@"C:\test"));
            signature = xmss.Sign(message);
            publicKeyPem = xmss.ExportSubjectPublicKeyInfoPem();
        }
        {
            using var xmss = new Xmss();
            xmss.ImportFromPem(publicKeyPem);
            Console.WriteLine($"Verification: {xmss.Verify(message, signature)}");
        }
    }
}
