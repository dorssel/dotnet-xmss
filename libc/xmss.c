// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

// WASM (.NET 10) requires that the object file has the same name as the DllImport/LibraryImport name.
// Previously, xmss/libxmss did not matter, but now it does.

#include "libxmss.c"  // NOLINT
