// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Security.Cryptography;

namespace Dorssel.Security.Cryptography;

/// <summary>
/// TODO
/// </summary>
public sealed class XmssMemoryStateManager()
    : IXmssStateManager, IDisposable
{
    readonly Dictionary<XmssKeyPart, byte[]?> State = new()
    {
        { XmssKeyPart.PrivateStateless, null },
        { XmssKeyPart.PrivateStateful, null },
        { XmssKeyPart.Public, null },
    };

    [StackTraceHidden]
    void ThrowIfInvalidPart(XmssKeyPart part)
    {
        if (!State.ContainsKey(part))
        {
            throw new ArgumentOutOfRangeException(nameof(part));
        }
    }

    /// <inheritdoc/>
    public void Store(XmssKeyPart part, ReadOnlySpan<byte> data)
    {
        lock (State)
        {
            ThrowIfInvalidPart(part);

            ObjectDisposedException.ThrowIf(IsDisposed, this);

            if (State[part] is not null)
            {
                throw new InvalidOperationException("Part already exists.");
            }
            State[part] = data.ToArray();
        }
    }

    /// <inheritdoc/>
    public void StoreStatefulPart(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data)
    {
        if (data.Length != expected.Length)
        {
            throw new ArgumentException("Expected data and new data must have the same size.");
        }

        lock (State)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);

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
    }

    /// <inheritdoc/>
    public void Load(XmssKeyPart part, Span<byte> destination)
    {
        lock (State)
        {
            ThrowIfInvalidPart(part);

            ObjectDisposedException.ThrowIf(IsDisposed, this);

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
    }

    /// <inheritdoc/>
    public void DeletePublicPart()
    {
        lock (State)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);

            State[XmssKeyPart.Public] = null;
        }
    }

    /// <inheritdoc/>
    public void DeleteAll()
    {
        lock (State)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);

            CryptographicOperations.ZeroMemory(State[XmssKeyPart.PrivateStateless]);
            CryptographicOperations.ZeroMemory(State[XmssKeyPart.PrivateStateful]);
            State[XmssKeyPart.PrivateStateless] = null;
            State[XmssKeyPart.PrivateStateful] = null;
            State[XmssKeyPart.Public] = null;
        }
    }

    bool IsDisposed;

    /// <inheritdoc/>
    public void Dispose()
    {
        lock (State)
        {
            if (!IsDisposed)
            {
                DeleteAll();
                IsDisposed = true;
            }
        }
    }
}
