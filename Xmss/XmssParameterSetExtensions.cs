// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography;

static class XmssParameterSetExtensions
{
    public static XmssParameterSetOID AsOID(this XmssParameterSet parameterSet)
    {
        return (XmssParameterSetOID)parameterSet;
    }
}
