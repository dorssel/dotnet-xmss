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
            Xmss.RegisterWithCryptoConfig();

            var oid = CryptoConfig.MapNameToOID("XMSS");
            Console.WriteLine($"Found OID for 'XMSS': {oid}");
#pragma warning disable IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code
            var alg = CryptoConfig.CreateFromName("XMSS");
#pragma warning restore IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code
            Console.WriteLine($"Created by CryptoConfig('XMSS'): {alg is not null}");
        }

        var message = new byte[] { 1, 2, 3 };
        byte[] signature;
        string publicKeyPem;

        {
            Console.WriteLine("Generating new key...");

            using var xmss = new Xmss();
            xmss.GeneratePrivateKey(new XmssEphemeralStateManager(), XmssParameterSet.XMSS_SHA2_10_256, false);
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

            publicKeyPem = xmss.ExportSubjectPublicKeyInfoPem();
            Console.WriteLine("Public Key:");
            Console.WriteLine(publicKeyPem);

            Console.WriteLine("Signing a message...");
            signature = xmss.Sign(message);
        }
        {
            using var xmss = new Xmss();
            xmss.ImportFromPem(publicKeyPem);
            Console.WriteLine($"Verification: {xmss.Verify(message, signature)}");
        }
    }
}
