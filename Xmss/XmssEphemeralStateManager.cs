// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

/// <summary>
/// TODO
/// </summary>
public sealed class XmssEphemeralStateManager()
    : IXmssStateManager
{
    /// <inheritdoc/>
    public void Store(XmssKeyPart part, ReadOnlySpan<byte> data)
    {
    }

    /// <inheritdoc/>
    public void StoreStatefulPart(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data)
    {
    }

    /// <inheritdoc/>
    public void Load(XmssKeyPart part, Span<byte> destination)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc/>
    public void DeletePublicPart()
    {
    }

    /// <inheritdoc/>
    public void Purge()
    {
    }
}
