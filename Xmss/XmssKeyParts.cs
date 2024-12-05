// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

[Flags]
public enum XmssKeyParts
{
    PrivateStateless = 0b001,
    PrivateStateful = 0b010,
    Public = 0b100,
}
