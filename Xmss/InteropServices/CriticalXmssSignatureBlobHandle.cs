// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace Dorssel.Security.Cryptography.InteropServices;

sealed class CriticalXmssSignatureBlobHandle() : CriticalXmssBlobHandle<XmssSignatureBlob>(false)
{
}
