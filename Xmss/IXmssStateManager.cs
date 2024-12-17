// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

public interface IXmssStateManager
{
    public void Store(XmssKeyPart part, ReadOnlySpan<byte> data);

    public void StoreStatefulPart(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data);

    public void Load(XmssKeyPart part, Span<byte> destination);

    void DeletePublicPart();

    void DeleteAll();
}
