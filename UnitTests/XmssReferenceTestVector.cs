﻿// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

sealed record XmssReferenceTestVector
{
    public static IReadOnlyList<XmssReferenceTestVector> All { get; }

    public static byte[] computeHash(params byte[][] buf)
    {
        using var shake = new SHAKE(128, 80);
        return shake.ComputeHash(buf.SelectMany(i => i).ToArray());
    }

    public string Name { get; }
    public string Type { get; }
    public int Oid { get; }
    public ReadOnlyMemory<byte> PublicKeyHash;
    public ReadOnlyMemory<byte> SignatureHash;

    XmssReferenceTestVector(string line)
    {
        var parts = line.Split(' ');

        Type = parts[0];
        Oid = int.Parse(parts[1]);
        Name = Type switch
        {
            "WOTS+" => XmssParameters.Lookup((XmssOid)Oid).WotsOID.ToString(),
            "XMSS" => ((XmssOid)Oid).ToString(),
            "XMSSMT" => ((XmssMTOid)Oid).ToString(),
            _ => throw new NotImplementedException(),
        };
        PublicKeyHash = Convert.FromHexString(parts[2]);
        SignatureHash = Convert.FromHexString(parts[3]);

        // NOTE: The WOTS+ test vectors contain an extra element that is only useful
        // for testing an implementation detail of the XMSS reference implementation;
        // we don't have a 'gen_leef_wots' function (which is not part of the standard).
    }

    static XmssReferenceTestVector()
    {
        // See: https://github.com/XMSS/xmss-reference
        //
        // This is the output of the 'vectors' command to generate Known-Answer-Tests.
        var testVectors = @"

                WOTS+ 1 a5df5a7785a48961552e 4443fb313e5b0c2e8bec fc27066a9b31c0069597
                WOTS+ 4 b60e1297f5c9b328c5e8 3ae3de6598456112261d 1ae375ab3af144099b3d
                WOTS+ 7 654c7f6754b55312197f a51bd20ef66e93d79464 70dac71617da61947011
                WOTS+ 10 e7462d29751df96bf5a4 ffb59bc9bf87e4e4b7f0 0cf456d0f4b02b341e12
                WOTS+ 13 adbec5b9ba94bff3447d b32683d5888df51aa074 58eb225e44f38082b356
                WOTS+ 16 e008635b776020636868 05d9a9d517021307b1a7 2ed530d278acdf27e01d
                WOTS+ 19 8f041a7c67b46fc80b0d 98a906af2d18429309f6 34457720369d5f7691e9
                XMSSMT 2 9df4c75282451bf2bc53 fd4ff4c18801147b2804
                XMSSMT 10 fdeb0cc4fed643bf70ce fbeb33a7aed7af7ea526
                XMSSMT 18 dbe6fc388fbd610b3401 2c2a66cae9a16414088d
                XMSSMT 26 3739e7d3668932d9ca44 ec8d62bb9d4ba74c6729
                XMSSMT 34 eef50cfa8f267939ad08 759e579a56097da369b5
                XMSSMT 42 2d6ae135fda1077788ca 09a73575932668ca5e8d
                XMSSMT 50 21d799da214da955d915 45f8be8e21f1af08c828
                XMSS 1 7de72d192121f414d4bb 8b6cb278d50a3694ca38
                XMSS 4 74ee7c42b4e42a424ed9 b9e63b0376a550eabe1b
                XMSS 7 764614ee2ce5e4bf0114 3e9035cffa0fd4be98bd
                XMSS 10 e47fe831b6ee463e2881 ce2dc09cd7ad8c87ae06
                XMSS 13 5933d4b1e696804718c7 6ec9da2e05da544d9c5d
                XMSS 16 cef3d38791d56efee1b3 9939a0f87502df5d1e31
                XMSS 19 7fa280e502275858b27b 7782c54424c9ca082926

            ".Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => new XmssReferenceTestVector(s));

        All = testVectors.ToList().AsReadOnly();
    }
}
