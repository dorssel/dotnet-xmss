// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

sealed class MemoryStateManager()
    : IXmssStateManager
{
    readonly Dictionary<XmssKeyParts, byte[]> State = new()
    {
        { XmssKeyParts.PrivateStateless, [] },
        { XmssKeyParts.PrivateStateful, [] },
        { XmssKeyParts.Public, [] },
    };

    public void Store(XmssKeyParts part, ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data)
    {
        if (!expected.IsEmpty)
        {
            if (State[part].Length != expected.Length)
            {
                throw new ArgumentException("Expected size mismatch.", nameof(expected));
            }
            if (!expected.SequenceEqual(State[part]))
            {
                throw new ArgumentException("Expected content mismatch.", nameof(expected));
            }
        }
        else if (State[part].Length != 0)
        {
            throw new ArgumentException("Expected size mismatch.", nameof(expected));
        }
        State[part] = data.ToArray();
    }

    public void Load(XmssKeyParts part, Span<byte> destination)
    {
        if (State[part].Length != destination.Length)
        {
            throw new ArgumentException("Part size mismatch.", nameof(destination));
        }
        State[part].CopyTo(destination);
    }

    public void SecureDelete()
    {
        State[XmssKeyParts.PrivateStateless] = [];
        State[XmssKeyParts.PrivateStateful] = [];
        State[XmssKeyParts.Public] = [];
    }

    public void DeletePublicPart()
    {
        State[XmssKeyParts.Public] = [];
    }
}
