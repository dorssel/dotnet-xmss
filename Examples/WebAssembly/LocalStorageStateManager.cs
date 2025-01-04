// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Blazored.LocalStorage;
using Dorssel.Security.Cryptography;

sealed class LocalStorageStateManager(ISyncLocalStorageService localStorage, string prefix)
    : IXmssStateManager
{
    static readonly Dictionary<XmssKeyPart, string> Keys = new()
    {
        { XmssKeyPart.PrivateStateless, "xmss_private_stateless" },
        { XmssKeyPart.PrivateStateful, "xmss_private_stateful" },
        { XmssKeyPart.Public, "xmss_public" },
    };
    readonly ISyncLocalStorageService LocalStorage = localStorage;
    readonly string Prefix = prefix;

    string GetKey(XmssKeyPart part)
    {
        return string.Concat(Prefix, ".", Keys[part]);
    }

    public void Store(XmssKeyPart part, ReadOnlySpan<byte> data)
    {
        var key = GetKey(part);
        if (LocalStorage.ContainKey(key))
        {
            throw new InvalidOperationException("Part already exists.");
        }
        LocalStorage.SetItem(key, data.ToArray());
    }

    public void StoreStatefulPart(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data)
    {
        if (data.Length != expected.Length)
        {
            throw new ArgumentException("Expected data and new data must have the same size.");
        }
        var key = GetKey(XmssKeyPart.PrivateStateful);
        var oldData = new byte[expected.Length];
        Load(XmssKeyPart.PrivateStateful, oldData);
        if (!expected.SequenceEqual(oldData))
        {
            throw new ArgumentException("Expected content mismatch.", nameof(expected));
        }
        LocalStorage.SetItem(key, data.ToArray());
    }

    public void Load(XmssKeyPart part, Span<byte> destination)
    {
        var key = GetKey(part);
        var data = LocalStorage.GetItem<byte[]>(key) ?? throw new InvalidOperationException("Part does not exist.");
        if (data.Length != destination.Length)
        {
            throw new ArgumentException("Data size mismatch.", nameof(destination));
        }
        data.CopyTo(destination);
    }

    public void DeletePublicPart()
    {
        LocalStorage.RemoveItem(GetKey(XmssKeyPart.Public));
    }

    public void Purge()
    {
        LocalStorage.RemoveItems([
            GetKey(XmssKeyPart.PrivateStateless),
            GetKey(XmssKeyPart.PrivateStateful),
            GetKey(XmssKeyPart.Public),
        ]);
    }
}
