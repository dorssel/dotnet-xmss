﻿// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;

namespace UnitTests;

[AttributeUsage(AttributeTargets.Method)]
sealed class XmssReferenceDataSourceAttribute(string TestVectorType)
        : Attribute
    , ITestDataSource
{
    public string TestVectorType { get; private set; } = TestVectorType;

    public IEnumerable<object[]> GetData(MethodInfo methodInfo)
    {
        return XmssReferenceTestVector.All.Where(tv => tv.Type == TestVectorType).Select(tv => new object[] { tv });
    }

    public string GetDisplayName(MethodInfo methodInfo, object?[]? data)
    {
        var testVector = data?.FirstOrDefault() as XmssReferenceTestVector;
        return $"{methodInfo.Name}({testVector?.Name})";
    }
}
