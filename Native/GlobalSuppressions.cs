// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "We follow the naming convention of the native library.")]
[assembly: SuppressMessage("Design", "CA1051:Do not declare visible instance fields", Justification = "Fix later")]
[assembly: SuppressMessage("Security", "CA5393:Do not use unsafe DllImportSearchPath value", Justification = "Under investigation")]
[assembly: SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Fix later")]
[assembly: SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "Fix later")]
[assembly: SuppressMessage("Interoperability", "CA1401:P/Invokes should not be visible", Justification = "Under investigation")]
