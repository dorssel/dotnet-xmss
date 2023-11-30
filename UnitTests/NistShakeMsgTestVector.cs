// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Text.RegularExpressions;

namespace UnitTests;

sealed partial record NistShakeMsgTestVector(int L, ReadOnlyMemory<byte> Msg, ReadOnlyMemory<byte> Output);

/// <summary>
/// These Known-Answer-Test (KAT) vectors are from the
/// <see href="https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#Testing">NIST Cryptographic Algorithm Validation Program</see>.
/// </summary>
sealed partial record NistShakeMsgTestVector
{
    public static IReadOnlyList<NistShakeMsgTestVector> All { get; }

    static NistShakeMsgTestVector()
    {
        var testVectors = new List<NistShakeMsgTestVector>();
        foreach (var file in Directory.GetFiles("shakebytetestvectors", "SHAKE*Msg.rsp"))
        {
            var L = int.Parse(FilenameRegex().Matches(file).Single().Groups[1].Value);
            var content = File.ReadAllText(file);
            // unused:
            // var Outputlen = int.Parse(Regex.Matches(content, @"\[Outputlen = (\d+)]").Single().Groups[1].Value);
            foreach (var match in LenRegex().Matches(content).Cast<Match>())
            {
                var Len = int.Parse(match.Groups[1].Value);
                var Msg = Convert.FromHexString(match.Groups[2].Value).Take(Len / 8).ToArray();
                var Output = Convert.FromHexString(match.Groups[3].Value);
                testVectors.Add(new(L, Msg, Output));
            }
        }
        foreach (var file in Directory.GetFiles("shakebytetestvectors", "SHAKE*VariableOut.rsp"))
        {
            var L = int.Parse(FilenameRegex().Matches(file).Single().Groups[1].Value);
            var content = File.ReadAllText(file);
            var InputLength = int.Parse(InputLengthRegex().Matches(content).Single().Groups[1].Value);
            foreach (var match in OutputRegex().Matches(content).Cast<Match>())
            {
                // unused:
                // var Outputlen = int.Parse(match.Groups[1].Value);
                var Msg = Convert.FromHexString(match.Groups[2].Value);
                var Output = Convert.FromHexString(match.Groups[3].Value);
                testVectors.Add(new(L, Msg, Output));
            }
        }
        All = testVectors.AsReadOnly();
    }

    [GeneratedRegex(@"SHAKE(\d+)[^\d]*\.rsp")]
    private static partial Regex FilenameRegex();

    [GeneratedRegex(@"Len = (\d+)\s*Msg = ([0-9a-fA-F]+)\s*Output = ([0-9a-fA-F]+)")]
    private static partial Regex LenRegex();

    [GeneratedRegex(@"\[Input Length = (\d+)]")]
    private static partial Regex InputLengthRegex();

    [GeneratedRegex(@"Outputlen = (\d+)\s*Msg = ([0-9a-fA-F]+)\s*Output = ([0-9a-fA-F]+)")]
    private static partial Regex OutputRegex();
}
