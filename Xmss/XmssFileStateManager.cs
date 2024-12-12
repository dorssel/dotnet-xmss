// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

public sealed class XmssFileStateManager(string path)
    : IXmssStateManager
{
    static readonly Dictionary<XmssKeyParts, string> FileNames = new()
    {
        { XmssKeyParts.PrivateStateless, "xmss_private_stateless" },
        { XmssKeyParts.PrivateStateful, "xmss_private_stateful" },
        { XmssKeyParts.Public, "xmss_public" },
    };
    readonly string Folder = path;

    string GetPartPath(XmssKeyParts part)
    {
        return Path.Combine(Folder, FileNames[part]);
    }

    public void Store(XmssKeyParts part, ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data)
    {
        using var file = File.Open(GetPartPath(part), FileMode.OpenOrCreate);
        if (!expected.IsEmpty)
        {
            if (file.Length != expected.Length)
            {
                throw new ArgumentException("Expected size mismatch.", nameof(expected));
            }
            var current = new byte[expected.Length];
            file.ReadExactly(current);
            if (!expected.SequenceEqual(current))
            {
                throw new ArgumentException("Expected content mismatch.", nameof(expected));
            }
            file.Position = 0;
        }
        else if (file.Length != 0)
        {
            throw new ArgumentException("Expected size mismatch.", nameof(expected));
        }
        if (file.Length > data.Length)
        {
            // truncate after first zeroizing the surplus
            file.Position = data.Length;
            file.Write(new byte[file.Length - data.Length]);
            file.SetLength(data.Length);
            file.Position = 0;
        }
        file.Write(data);
        file.Flush();
    }

    public void Load(XmssKeyParts part, Span<byte> destination)
    {
        using var file = File.OpenRead(GetPartPath(part));
        if (file.Length != destination.Length)
        {
            throw new ArgumentException("File size mismatch.", nameof(destination));
        }
        file.ReadExactly(destination);
    }

    public void SecureDelete()
    {
        // TODO: zeroize data if files exist
        File.Delete(GetPartPath(XmssKeyParts.PrivateStateless));
        File.Delete(GetPartPath(XmssKeyParts.PrivateStateful));
        DeletePublicPart();
    }

    public void DeletePublicPart()
    {
        File.Delete(GetPartPath(XmssKeyParts.Public));
    }
}
