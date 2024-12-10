// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

public interface IXmssStateManager
{
    public void Store(XmssKeyParts part, ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data);

    public void Load(XmssKeyParts part, Span<byte> destination);

    void SecureDelete();

    void DeletePublicPart();
}
