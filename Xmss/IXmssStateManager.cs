// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

public interface IXmssStateManager
    : IDisposable
{
    XmssKeyParts AvailableKeyParts { get; }

    void Lock();

    void Unlock();

    void Delete();

    public void Store(XmssKeyParts part, ReadOnlySpan<byte> data);

    public void Load(XmssKeyParts part, Span<byte> destination);
}
