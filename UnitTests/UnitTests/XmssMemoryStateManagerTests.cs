// SPDX-FileCopyrightText: 2025 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class XmssMemoryStateManagerTests
{
    [TestMethod]
    public void Constructor()
    {
        using var stateManager = new XmssMemoryStateManager();
    }

    [TestMethod]
    public void Store()
    {
        using var stateManager = new XmssMemoryStateManager();

        stateManager.Store(XmssKeyPart.Public, [1]);
    }

    [TestMethod]
    public void Store_Exists()
    {
        using var stateManager = new XmssMemoryStateManager();

        stateManager.Store(XmssKeyPart.Public, [1]);

        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            stateManager.Store(XmssKeyPart.Public, [2]);
        });
    }

    [TestMethod]
    public void StoreStoreStatefulPart()
    {
        using var stateManager = new XmssMemoryStateManager();
        stateManager.Store(XmssKeyPart.PrivateStateful, [1]);

        stateManager.StoreStatefulPart([1], [2]);
    }

    [TestMethod]
    public void StoreStoreStatefulPart_ExpectedAndDataMismatch()
    {
        using var stateManager = new XmssMemoryStateManager();
        stateManager.Store(XmssKeyPart.PrivateStateful, [1]);

        Assert.ThrowsException<ArgumentException>(() =>
        {
            stateManager.StoreStatefulPart([1], [2, 3]);
        });
    }

    [TestMethod]
    public void StoreStoreStatefulPart_FileNotExists()
    {
        using var stateManager = new XmssMemoryStateManager();

        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            stateManager.StoreStatefulPart([1], [2]);
        });
    }

    [TestMethod]
    public void StoreStoreStatefulPart_FileSizeMismatch()
    {
        using var stateManager = new XmssMemoryStateManager();
        stateManager.Store(XmssKeyPart.PrivateStateful, [1]);

        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            stateManager.StoreStatefulPart([1, 2], [3, 4]);
        });
    }

    [TestMethod]
    public void StoreStoreStatefulPart_FileContentMismatch()
    {
        using var stateManager = new XmssMemoryStateManager();
        stateManager.Store(XmssKeyPart.PrivateStateful, [1]);

        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            stateManager.StoreStatefulPart([2], [3]);
        });
    }

    [TestMethod]
    public void Load()
    {
        var data = new byte[] { 1, 2, 3 };

        using var stateManager = new XmssMemoryStateManager();
        stateManager.Store(XmssKeyPart.Public, data);

        var read = new byte[data.Length];
        stateManager.Load(XmssKeyPart.Public, read);

        CollectionAssert.AreEqual(data, read);
    }

    [TestMethod]
    public void Load_WrongSize()
    {
        var data = new byte[] { 1, 2, 3 };

        using var stateManager = new XmssMemoryStateManager();
        stateManager.Store(XmssKeyPart.Public, data);

        var read = new byte[data.Length - 1];
        Assert.ThrowsException<ArgumentException>(() =>
        {
            stateManager.Load(XmssKeyPart.Public, read);
        });
    }

    [TestMethod]
    public void Load_PartNotExists()
    {
        using var stateManager = new XmssMemoryStateManager();

        Assert.ThrowsException<InvalidOperationException>(() =>
        {
            stateManager.Load(XmssKeyPart.Public, new byte[1]);
        });
    }

    [TestMethod]
    public void Load_UnknownPart()
    {
        var data = new byte[] { 1, 2, 3 };

        using var stateManager = new XmssMemoryStateManager();

        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            stateManager.Load(Enum.GetValues<XmssKeyPart>().Max() + 1, new byte[1]);
        });
    }

    [TestMethod]
    public void DeletePublicPart()
    {
        using var stateManager = new XmssMemoryStateManager();
        stateManager.Store(XmssKeyPart.Public, [1]);

        stateManager.DeletePublicPart();


    }

    [TestMethod]
    public void DeletePublicPart_PartNotExists()
    {
        using var stateManager = new XmssMemoryStateManager();

        stateManager.DeletePublicPart();
    }

    [TestMethod]
    public void Purge()
    {
        using var stateManager = new XmssMemoryStateManager();
        stateManager.Store(XmssKeyPart.PrivateStateless, [1]);
        stateManager.Store(XmssKeyPart.PrivateStateful, [2]);
        stateManager.Store(XmssKeyPart.Public, [3]);

        stateManager.Purge();
    }

    [TestMethod]
    public void Purge_PartsNotExist()
    {
        using var stateManager = new XmssMemoryStateManager();

        stateManager.Purge();
    }
}
