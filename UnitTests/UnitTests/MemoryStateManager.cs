// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

sealed class MemoryStateManager()
    : IXmssStateManager
{
    readonly Dictionary<XmssKeyPart, byte[]?> State = new()
    {
        { XmssKeyPart.PrivateStateless, null },
        { XmssKeyPart.PrivateStateful, null },
        { XmssKeyPart.Public, null },
    };

    public byte[]? GetPartData(XmssKeyPart part)
    {
        return State[part];
    }

    readonly Queue<bool> PlannedSuccess = new();

    public void Setup(bool success = true)
    {
        PlannedSuccess.Enqueue(success);
    }

    void ThrowIfPlanned()
    {
        if (PlannedSuccess.TryDequeue(out var success) && !success)
        {
            throw new InvalidOperationException("Planned failure.");
        }
    }

    public void Store(XmssKeyPart part, ReadOnlySpan<byte> data)
    {
        ThrowIfPlanned();

        if (State[part] is not null)
        {
            throw new InvalidOperationException("Part already exists.");
        }
        State[part] = data.ToArray();
    }

    public void StoreStatefulPart(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data)
    {
        ThrowIfPlanned();

        if (State[XmssKeyPart.PrivateStateful] is not byte[] oldData)
        {
            throw new InvalidOperationException("Part does not exist.");
        }
        if (!expected.SequenceEqual(oldData))
        {
            throw new ArgumentException("Expected content mismatch.", nameof(expected));
        }
        State[XmssKeyPart.PrivateStateful] = data.ToArray();
    }

    public void Load(XmssKeyPart part, Span<byte> destination)
    {
        ThrowIfPlanned();

        if (State[part] is not byte[] data)
        {
            throw new InvalidOperationException("Part does not exist.");
        }
        if (data.Length != destination.Length)
        {
            throw new ArgumentException("Part size mismatch.", nameof(destination));
        }
        data.CopyTo(destination);
    }

    public void DeletePublicPart()
    {
        ThrowIfPlanned();

        State[XmssKeyPart.Public] = null;
    }

    public void DeleteAll()
    {
        ThrowIfPlanned();

        State[XmssKeyPart.PrivateStateless] = null;
        State[XmssKeyPart.PrivateStateful] = null;
        State[XmssKeyPart.Public] = null;
    }
}
