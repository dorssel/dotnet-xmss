// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.ComponentModel;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace System.Runtime.CompilerServices;
#pragma warning restore IDE0130 // Namespace does not match folder structure

/// <summary>
/// Fix for using C# 9 feature in netstandard2.0.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
sealed record IsExternalInit;
