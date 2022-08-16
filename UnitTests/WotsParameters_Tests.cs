// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class WotsParameters_Tests
{
    [TestMethod]
    public void LookupAll()
    {
        foreach (var oid in Enum.GetValues<WotsOid>())
        {
            var parameters = WotsParameters.Lookup(oid);
            Assert.AreEqual(oid, parameters.OID);
            Assert.AreEqual(parameters.len, parameters.len_1 + parameters.len_2);
        }
    }
}
