// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;
using System.Security.Cryptography;

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
        /*
        {
            using var ec = ECDsa.Create();
            var parameters = ec.ExportParameters(false);
            using var ec2 = ECDsa.Create(parameters);
            var signature = ec2.SignData([1, 2, 3, 4], HashAlgorithmName.SHA256);
            _ = signature;
        }
        */
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
            // generate new key

            var stateManager = new XmssFileStateManager(@"C:\test");
            stateManager.SecureDelete();
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
                    xmss.GeneratePublicKeyAsync(progress =>
                    {
                        if (oldPercentage < (int)progress)
                        {
                            oldPercentage = (int)progress;
                            Console.Write($"\r{(int)progress,3}%");
                        }
                    }, cancellationTokenSource.Token).Wait();
                }
                catch (AggregateException ex) when (ex.GetBaseException() is OperationCanceledException)
                {
                    Console.WriteLine();
                    Console.WriteLine("Canceled");
                    return;
                }
            }
            Console.WriteLine();
            Console.WriteLine(xmss.ExportSubjectPublicKeyInfoPem());
            _ = xmss.Sign([1, 2, 3]);
            _ = xmss.Sign([4, 5, 6]);
        }
        var message = new byte[] { 7, 8, 9 };
        byte[] signature;
        string publicKeyPem;
        {
            // reuse same key

            using var xmss = new Xmss();
            xmss.ImportPrivateKey(new XmssFileStateManager(@"C:\test"));
            signature = xmss.Sign(message);
            publicKeyPem = xmss.ExportSubjectPublicKeyInfoPem();
            Console.WriteLine($"verification: {xmss.Verify(message, signature)}");
        }
        {
            // verify using public key only
            using var xmss = new Xmss();
            xmss.ImportFromPem(publicKeyPem);
            Console.WriteLine($"verification (pubkey only): {xmss.Verify(message, signature)}");
        }
    }
}
