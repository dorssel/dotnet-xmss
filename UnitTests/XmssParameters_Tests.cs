// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class XmssParameters_Tests
{
    [TestMethod]
    public void LookupAll()
    {
        foreach (var oid in Enum.GetValues<XmssOid>())
        {
            var parameters = XmssParameters.Lookup(oid);
            Assert.AreEqual(oid, parameters.OID);
            Assert.IsTrue(oid.ToString().Contains($"_{parameters.h}_"));
        }
    }
}
