// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace UnitTests;

sealed class TestRandomNumberGenerator
    : RandomNumberGenerator
{
    public TestRandomNumberGenerator(ReadOnlySpan<byte> data)
    {
        Data = data.ToArray();
    }

    readonly byte[] Data;

    public int Position { get; private set; }

    public override void GetBytes(byte[] data)
    {
        Data.AsSpan(Position, data.Length).CopyTo(data);
        Position += data.Length;
    }

    public bool EndOfData => Position == Data.Length;
}
