﻿// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

// This file is used by Code Analysis to maintain SuppressMessage
// attributes that are applied to this project.
// Project-level suppressions either have no target or are given
// a specific target and scoped to a namespace, type, member, etc.

using System.Diagnostics.CodeAnalysis;

[assembly: SuppressMessage("Security", "CA5393:Do not use unsafe DllImportSearchPath value", Justification = "Required to load native runtime library.")]
