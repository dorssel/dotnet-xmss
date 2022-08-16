// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.ComponentModel;

namespace System.Runtime.CompilerServices;

/// <summary>
/// Fix for using C# 9 feature in netstandard2.0.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
record IsExternalInit;
