// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using NativeHelper;

namespace XmssUnitTests;

[TestClass]
sealed unsafe class AssemblyTests
{
    [AssemblyInitialize]
    public static void AssemblyInitialize(TestContext testContext)
    {
        _ = testContext;
        NativeLoader.Setup();
    }
}
