// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

[Flags]
public enum XmssKeyParts
{
    ParameterSet = 0b0001,
    PrivateStateless = 0b0010,
    PrivateStateful = 0b0100,
    Public = 0b1000,
}
