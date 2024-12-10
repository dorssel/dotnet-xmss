// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Blazored.LocalStorage;
using Dorssel.Security.Cryptography;

sealed class LocalStorageStateManager(ISyncLocalStorageService localStorage, string prefix)
    : IXmssStateManager
{
    static readonly Dictionary<XmssKeyParts, string> FileNames = new()
    {
        { XmssKeyParts.PrivateStateless, "xmss_private_stateless" },
        { XmssKeyParts.PrivateStateful, "xmss_private_stateful" },
        { XmssKeyParts.Public, "xmss_public" },
    };
    readonly ISyncLocalStorageService LocalStorage = localStorage;
    readonly string Prefix = prefix;

    string GetPartPath(XmssKeyParts part)
    {
        return Path.Combine(Prefix, FileNames[part]);
    }

    public void Load(XmssKeyParts part, Span<byte> destination)
    {
        var data = LocalStorage.GetItem<byte[]>(GetPartPath(part)) ?? throw new FileNotFoundException(GetPartPath(part));
        if (data.Length != destination.Length)
        {
            throw new ArgumentException("Data size mismatch.", nameof(destination));
        }
        data.CopyTo(destination);
    }

    public void Store(XmssKeyParts part, ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data)
    {
        LocalStorage.SetItem(GetPartPath(part), data.ToArray());
    }

    public void SecureDelete()
    {
        LocalStorage.RemoveItems([
            GetPartPath(XmssKeyParts.PrivateStateless),
            GetPartPath(XmssKeyParts.PrivateStateful),
            GetPartPath(XmssKeyParts.Public),
        ]);
    }

    public void DeletePublicPart()
    {
        LocalStorage.RemoveItem(GetPartPath(XmssKeyParts.Public));
    }
}
