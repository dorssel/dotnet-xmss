// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

[Flags]
public enum XmssKeyParts
{
    PrivateStateless = 1,
    PrivateStateful,
    Public,
}
