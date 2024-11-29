// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Buffers.Binary;
using System.Security.Cryptography;
using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography;

static class XmssParameterSetExtensions
{
    public static XmssParameterSetOID AsOID(this XmssParameterSet parameterSet)
    {
        return (XmssParameterSetOID)parameterSet;
    }

    public static byte[] ToBigEndian(this XmssParameterSet parameterSet)
    {
        var bytes = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32BigEndian(bytes, (int)parameterSet);
        return bytes;
    }

    public static void FromBigEndian(this ref XmssParameterSet parameterSet, byte[] data)
    {
        if (data.Length != sizeof(int))
        {
            throw new ArgumentException("Wrong size of data.", nameof(data));
        }
        var ps = (XmssParameterSet)BinaryPrimitives.ReadInt32BigEndian(data);
        if (!Enum.IsDefined(ps) || ps == XmssParameterSet.None)
        {
            throw new CryptographicException("Unsupported parameter set.");
        }
        parameterSet = ps;
    }
}
