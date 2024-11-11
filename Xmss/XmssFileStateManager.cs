// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

public sealed class XmssFileStateManager
    : IXmssStateManager
{
    static readonly Dictionary<XmssKeyParts, string> FileNames = new()
    {
        { XmssKeyParts.ParameterSet, "xmss_parameter_set" },
        { XmssKeyParts.PrivateStateless, "xmss_private_stateless" },
        { XmssKeyParts.PrivateStateful, "xmss_private_stateful" },
        { XmssKeyParts.Public, "xmss_public" },
    };

    public XmssFileStateManager(string path)
    {
        Folder = path;
    }

    string Folder;

    string GetPartPath(XmssKeyParts part) => Path.Combine(Folder, FileNames[part]);

    public XmssKeyParts AvailableKeyParts => XmssKeyParts.ParameterSet | XmssKeyParts.PrivateStateless | XmssKeyParts.PrivateStateful | XmssKeyParts.Public;

    public void Store(XmssKeyParts part, ReadOnlySpan<byte> data)
    {
        using var file = File.Create(GetPartPath(part));
        file.Write(data);
        file.Flush();
    }

    public byte[] Load(XmssKeyParts part)
    {
        return File.ReadAllBytes(GetPartPath(part));
    }

    public void Lock()
    {
        throw new NotImplementedException();
    }

    public void Unlock()
    {
        throw new NotImplementedException();
    }

    public void Delete()
    {
        File.Delete(GetPartPath(XmssKeyParts.ParameterSet));
        File.Delete(GetPartPath(XmssKeyParts.PrivateStateless));
        File.Delete(GetPartPath(XmssKeyParts.PrivateStateful));
        File.Delete(GetPartPath(XmssKeyParts.Public));
    }

    public void Dispose()
    {
    }
}
