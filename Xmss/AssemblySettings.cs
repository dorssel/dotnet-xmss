// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: DisableRuntimeMarshalling]
[assembly: InternalsVisibleTo("Internal.UnitTests")]
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
