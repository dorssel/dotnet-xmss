// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Buffers;

namespace Dorssel.Security.Cryptography;

public sealed class XmssFileStateManager(string path)
    : IXmssStateManager
{
    static readonly Dictionary<XmssKeyPart, string> FileNames = new()
    {
        { XmssKeyPart.PrivateStateless, "xmss_private_stateless" },
        { XmssKeyPart.PrivateStateful, "xmss_private_stateful" },
        { XmssKeyPart.Public, "xmss_public" },
    };
    readonly string Folder = path;

    bool TryGetPath(XmssKeyPart part, out string partPath)
    {
        if (!FileNames.TryGetValue(part, out var fileName))
        {
            partPath = string.Empty;
            return false;
        }
        partPath = Path.Combine(Folder, fileName);
        return true;
    }

    string GetPath(XmssKeyPart part)
    {
        return TryGetPath(part, out var partPath) ? partPath : throw new ArgumentOutOfRangeException(nameof(part));
    }

    public void Store(XmssKeyPart part, ReadOnlySpan<byte> data)
    {
        using var file = File.Open(GetPath(part), FileMode.CreateNew);
        file.Write(data);
        file.Flush();
    }

    public void StoreStatefulPart(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data)
    {
        if (data.Length != expected.Length)
        {
            throw new ArgumentException("Expected data and new data must have the same size.");
        }
        using var file = File.Open(GetPath(XmssKeyPart.PrivateStateful), FileMode.Open);
        if (file.Length != expected.Length)
        {
            throw new ArgumentException("Expected size mismatch.", nameof(expected));
        }
        var possiblyOversizedCurrent = ArrayPool<byte>.Shared.Rent(expected.Length);
        try
        {
            var current = possiblyOversizedCurrent.AsSpan(0, expected.Length);
            file.ReadExactly(current);
            if (!current.SequenceEqual(expected))
            {
                throw new ArgumentException("Expected content mismatch.", nameof(expected));
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(possiblyOversizedCurrent);
        }
        file.Position = 0;
        file.Write(data);
        file.Flush();
    }

    public void Load(XmssKeyPart part, Span<byte> destination)
    {
        using var file = File.OpenRead(GetPath(part));
        if (file.Length != destination.Length)
        {
            throw new ArgumentException("File size mismatch.", nameof(destination));
        }
        file.ReadExactly(destination);
    }

    public void DeletePublicPart()
    {
        File.Delete(GetPath(XmssKeyPart.Public));
    }

    static void SecureDelete(string path)
    {
        if (!File.Exists(path))
        {
            return;
        }
        using var file = File.Open(path, FileMode.Open);
        var remaining = file.Length;
        var possiblyOversizedZeros = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            Array.Clear(possiblyOversizedZeros, 0, 4096);
            var zeros = possiblyOversizedZeros.AsSpan(0, 4096);
            while (remaining > 0)
            {
                var count = unchecked((int)Math.Min(remaining, zeros.Length));
                file.Write(zeros[..count]);
                remaining -= count;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(possiblyOversizedZeros);
        }
        file.Flush();
        file.Close();
        File.Delete(path);
    }

    public void DeleteAll()
    {
        SecureDelete(GetPath(XmssKeyPart.PrivateStateless));
        SecureDelete(GetPath(XmssKeyPart.PrivateStateful));
        DeletePublicPart();
    }
}
