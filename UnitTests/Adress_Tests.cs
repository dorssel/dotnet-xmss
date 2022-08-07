// SPDX-FileCopyrightText: 2022 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

[TestClass]
sealed class Address_Tests
{
    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(int.MaxValue)]
    public void LayerAddress(int layer_address)
    {
        var ADRS = new Address
        {
            layer_address = layer_address,
        };
        Assert.AreEqual(layer_address, ADRS.layer_address);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(long.MaxValue)]
    public void TreeAddress(long tree_address)
    {
        var ADRS = new Address
        {
            tree_address = tree_address,
        };
        Assert.AreEqual(tree_address, ADRS.tree_address);
    }

    [TestMethod]
    [DataRow(AddressType.OTS)]
    [DataRow(AddressType.L_tree)]
    [DataRow(AddressType.Hash_tree)]
    public void Type(AddressType type)
    {
        var ADRS = new Address
        {
            type = type,
        };
        Assert.AreEqual(type, ADRS.type);
    }

    [TestMethod]
    public void Type_SetClearsLowerFields()
    {
        var ADRS = new Address
        {
            layer_address = 1,
            tree_address = 2,
            type = AddressType.OTS,
            OTS_address = 4,
            chain_address = 5,
            hash_address = 6,
            keyAndMask = 7,
        };
        Assert.AreEqual(1, ADRS.layer_address);
        Assert.AreEqual(2, ADRS.tree_address);
        Assert.AreEqual(AddressType.OTS, ADRS.type);
        Assert.AreEqual(4, ADRS.OTS_address);
        Assert.AreEqual(5, ADRS.chain_address);
        Assert.AreEqual(6, ADRS.hash_address);
        Assert.AreEqual(7, ADRS.keyAndMask);

        ADRS.type = AddressType.OTS;

        Assert.AreEqual(1, ADRS.layer_address);
        Assert.AreEqual(2, ADRS.tree_address);
        Assert.AreEqual(AddressType.OTS, ADRS.type);
        Assert.AreEqual(0, ADRS.OTS_address);
        Assert.AreEqual(0, ADRS.chain_address);
        Assert.AreEqual(0, ADRS.hash_address);
        Assert.AreEqual(0, ADRS.keyAndMask);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(int.MaxValue)]
    public void OtsAddress(int OTS_address)
    {
        var ADRS = new Address
        {
            type = AddressType.OTS,
            OTS_address = OTS_address,
        };
        Assert.AreEqual(OTS_address, ADRS.OTS_address);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(int.MaxValue)]
    public void ChainAddress(int chain_address)
    {
        var ADRS = new Address
        {
            type = AddressType.OTS,
            chain_address = chain_address,
        };
        Assert.AreEqual(chain_address, ADRS.chain_address);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(int.MaxValue)]
    public void HashAddress(int hash_address)
    {
        var ADRS = new Address
        {
            type = AddressType.OTS,
            hash_address = hash_address,
        };
        Assert.AreEqual(hash_address, ADRS.hash_address);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(int.MaxValue)]
    public void KeyAndMask(int keyAndMask)
    {
        var ADRS = new Address
        {
            type = AddressType.OTS,
            keyAndMask = keyAndMask,
        };
        Assert.AreEqual(keyAndMask, ADRS.keyAndMask);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(int.MaxValue)]
    public void LTreeAddress(int L_tree_address)
    {
        var ADRS = new Address
        {
            type = AddressType.L_tree,
            L_tree_address = L_tree_address,
        };
        Assert.AreEqual(L_tree_address, ADRS.L_tree_address);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(int.MaxValue)]
    public void TreeHeight(int tree_height)
    {
        var ADRS = new Address
        {
            type = AddressType.L_tree,
            tree_height = tree_height,
        };
        Assert.AreEqual(tree_height, ADRS.tree_height);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(int.MaxValue)]
    public void TreeIndex(int tree_index)
    {
        var ADRS = new Address
        {
            type = AddressType.L_tree,
            tree_index = tree_index,
        };
        Assert.AreEqual(tree_index, ADRS.tree_index);
    }
}
