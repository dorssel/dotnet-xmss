// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using System.Reflection;

namespace UnitTests;

[AttributeUsage(AttributeTargets.Method)]
sealed class NistShakeMsgDataSourceAttribute
    : Attribute
    , ITestDataSource
{
    public NistShakeMsgDataSourceAttribute()
    {
    }

    public IEnumerable<object[]> GetData(MethodInfo methodInfo)
    {
        return NistShakeMsgTestVector.All.Select(tv => new object[] { tv });
    }

    public string GetDisplayName(MethodInfo methodInfo, object?[]? data)
    {
        var testVector = data?.FirstOrDefault() as NistShakeMsgTestVector;
        return $"{methodInfo.Name}({testVector?.L},{testVector?.Msg.Length}=>{testVector?.Output.Length})";
    }
}
