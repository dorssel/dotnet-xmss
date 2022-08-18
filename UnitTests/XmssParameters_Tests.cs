// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class XmssParameters_Tests
{
    [TestMethod]
    public void Lookup()
    {
        foreach (var oid in Enum.GetValues<XmssOid>())
        {
            var parameters = XmssParameters.Lookup(oid);
            Assert.AreEqual(oid, parameters.OID);
        }
    }

    [TestMethod]
    public void Sanity()
    {
        foreach (var oid in Enum.GetValues<XmssOid>())
        {
            var parameters = XmssParameters.Lookup(oid);
            var name = parameters.OID.ToString();

            // Expected format:
            //      XMSS_<hash name>_<tree height>_<n in bits>
            var nameParts = name.Split("_").ToArray();

            Assert.AreEqual(4, nameParts.Length);

            Assert.AreEqual("XMSS", nameParts[0]);

            Assert.AreEqual(int.Parse(nameParts[2]), parameters.h);

            Assert.AreEqual($"WOTSP_{nameParts[1]}_{nameParts[3]}", parameters.WotsOID.ToString());
        }
    }
}
