// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

/// <summary>
/// Manages the state of an XMSS key.
/// </summary>
/// <remarks>
/// All methods may throw any <see cref="Exception"/>; the derived exception types are just suggestions for special cases.
/// The <see cref="Xmss"/> class will wrap all exceptions in an <see cref="XmssStateManagerException"/>.
/// </remarks>
public interface IXmssStateManager
{
    /// <summary>
    /// Stores a new key part; the part must not already exist.
    /// </summary>
    /// <param name="part">The part of the key to be stored.</param>
    /// <param name="data">The data to be stored.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="part"/> is not an <see cref="XmssKeyPart"/>.</exception>
    /// <exception cref="InvalidOperationException"><paramref name="part"/> already exists.</exception>
    /// <exception cref="Exception">The data was not stored successfully.</exception>
    void Store(XmssKeyPart part, ReadOnlySpan<byte> data);

    /// <summary>
    /// Updates the stored data for <see cref="XmssKeyPart.PrivateStateful"/>.
    /// </summary>
    /// <remarks>
    /// The data for <see cref="XmssKeyPart.PrivateStateful"/> has a fixed, predetermined size.
    /// Therefore, <paramref name="expected"/> and <paramref name="data"/> shall be of equal length.
    /// </remarks>
    /// <param name="expected">The expected current data.</param>
    /// <param name="data">The new data to be stored.</param>
    /// <exception cref="ArgumentException"><paramref name="expected"/> and <paramref name="data"/> have a different length.</exception>
    /// <exception cref="InvalidOperationException"><see cref="XmssKeyPart.PrivateStateful"/> does not exist.
    ///
    /// -or-
    ///
    /// <paramref name="expected"/> does not match the current data for <see cref="XmssKeyPart.PrivateStateful"/>.</exception>
    /// <exception cref="Exception">The data was not stored successfully.</exception>
    void StoreStatefulPart(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data);

    /// <summary>
    /// Loads an existing key part.
    /// </summary>
    /// <param name="part">The part of the key to be loaded.</param>
    /// <param name="destination">The buffer to receive the data.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="part"/> is not an <see cref="XmssKeyPart"/>.</exception>
    /// <exception cref="InvalidOperationException"><paramref name="part"/> does not exist.</exception>
    /// <exception cref="ArgumentException">The length of <paramref name="destination"/> does not match the length of the stored data.</exception>
    /// <exception cref="Exception">The data was not loaded successfully.</exception>
    void Load(XmssKeyPart part, Span<byte> destination);

    /// <summary>
    /// Deletes any stored data for <see cref="XmssKeyPart.Public"/>.
    /// <para>
    /// If <see cref="XmssKeyPart.Public"/> does not exist, this method simply returns.
    /// </para>
    /// </summary>
    /// <exception cref="Exception"><see cref="XmssKeyPart.Public"/> exists and was not deleted successfully.</exception>
    void DeletePublicPart();

    /// <summary>
    /// Securely deletes (purges) any stored data for every <see cref="XmssKeyPart"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="XmssKeyPart.PrivateStateless"/> and <see cref="XmssKeyPart.PrivateStateful"/> must be securely erased
    /// (purged), as they contain confidential information. <see cref="XmssKeyPart.Public"/> may simply be deleted.
    /// </remarks>
    /// <exception cref="Exception">At least one key part was not purged.</exception>
    void Purge();
}
