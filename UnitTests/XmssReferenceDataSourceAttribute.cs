// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;

namespace UnitTests;

[AttributeUsage(AttributeTargets.Method)]
sealed class XmssReferenceDataSourceAttribute
    : Attribute
    , ITestDataSource
{
    public string TestVectorType { get; private set; }

    public XmssReferenceDataSourceAttribute(string TestVectorType)
    {
        this.TestVectorType = TestVectorType;
    }

    public IEnumerable<object[]> GetData(MethodInfo methodInfo)
    {
        return XmssReferenceTestVector.All.Where(tv => tv.Type == TestVectorType).Select(tv => new object[] { tv });
    }

    public string GetDisplayName(MethodInfo methodInfo, object[] data)
    {
        var testVector = (XmssReferenceTestVector)data[0];
        return $"{methodInfo.Name}({testVector.Name})";
    }
}
