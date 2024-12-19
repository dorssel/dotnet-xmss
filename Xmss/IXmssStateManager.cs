// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

/// <summary>
/// TODO
/// </summary>
public interface IXmssStateManager
{
    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="part">TODO</param>
    /// <param name="data">TODO</param>
    void Store(XmssKeyPart part, ReadOnlySpan<byte> data);

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="expected">TODO</param>
    /// <param name="data">TODO</param>
    void StoreStatefulPart(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data);

    /// <summary>
    /// TODO
    /// </summary>
    /// <param name="part">TODO</param>
    /// <param name="destination">TODO</param>
    void Load(XmssKeyPart part, Span<byte> destination);

    /// <summary>
    /// TODO
    /// </summary>
    void DeletePublicPart();

    /// <summary>
    /// TODO
    /// </summary>
    void DeleteAll();
}
