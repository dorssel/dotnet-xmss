// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class WotsParameters_Tests
{
    [TestMethod]
    public void Lookup()
    {
        foreach (var oid in Enum.GetValues<WotsOid>())
        {
            var parameters = WotsParameters.Lookup(oid);
            Assert.AreEqual(oid, parameters.OID);
        }
    }

    [TestMethod]
    public void Sanity()
    {
        foreach (var oid in Enum.GetValues<WotsOid>())
        {
            var parameters = WotsParameters.Lookup(oid);
            var name = parameters.OID.ToString();

            // Expected format:
            //      WOTSP_<hash name>_<n in bits>
            var nameParts = name.Split("_").ToArray();
            Assert.AreEqual(3, nameParts.Length);

            Assert.AreEqual("WOTSP", nameParts[0]);

            Assert.AreEqual(int.Parse(nameParts[2]), parameters.n * 8);

            // See RFC 8391, Section 3.1.1:
            //      w ∈ {4, 16}
            CollectionAssert.Contains(new[] { 4, 16 }, parameters.w);

            // See RFC 8391, Section 3.1.1:
            //      len = len_1 + len_2
            Assert.AreEqual(parameters.len_1 + parameters.len_2, parameters.len);

            // See RFC 8391, Section 3.1.1:
            //      len_1 = ceil(8n / lg(w))
            Assert.AreEqual((int)Math.Ceiling(8 * parameters.n / Math.Log2(parameters.w)), parameters.len_1);

            // See RFC 8391, Section 3.1.1:
            //      len_2 = floor(lg(len_1 * (w - 1)) / lg(w)) + 1
            Assert.AreEqual((int)Math.Floor(Math.Log2(parameters.len_1 * (parameters.w - 1)) / Math.Log2(parameters.w)) + 1, parameters.len_2);

            switch (nameParts[1])
            {
                case "SHA2":
                case "SHAKE":
                case "SHAKE256":
                    if (parameters.n == 24)
                    {
                        // See NIST SP 800-208, Sections 5.2 and 5.4
                        Assert.AreEqual(4, parameters.toByteLength);
                    }
                    else
                    {
                        // See RFC 8391, Section 5.1
                        Assert.AreEqual(parameters.n, parameters.toByteLength);
                    }
                    break;
                default:
                    throw new InternalTestFailureException("unrecognized hash algorithm");
            }
        }
    }
}
