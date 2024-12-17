// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class XmssFileStateManagerTests
{
    public TestContext TestContext { get; set; }

    [TestMethod]
    public void Constructor()
    {
        using var directory = new TemporaryDirectory(TestContext, false);

        _ = new XmssFileStateManager(directory.AbsolutePath);
    }

    [TestMethod]
    public void Store()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyPart.Public, [1]);
    }

    [TestMethod]
    public void StoreStoreStatefulPart()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyPart.PrivateStateful, [1]);

        stateManager.StoreStatefulPart([1], [2]);
    }

    [TestMethod]
    public void StoreStoreStatefulPart_ExpectedAndDataMismatch()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyPart.PrivateStateful, [1]);

        Assert.ThrowsException<ArgumentException>(() =>
        {
            stateManager.StoreStatefulPart([1], [2, 3]);
        });
    }

    [TestMethod]
    public void StoreStoreStatefulPart_FileNotExists()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);

        Assert.ThrowsException<FileNotFoundException>(() =>
        {
            stateManager.StoreStatefulPart([1], [2]);
        });
    }

    [TestMethod]
    public void StoreStoreStatefulPart_FileSizeMismatch()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyPart.PrivateStateful, [1]);

        Assert.ThrowsException<ArgumentException>(() =>
        {
            stateManager.StoreStatefulPart([1, 2], [3, 4]);
        });
    }

    [TestMethod]
    public void StoreStoreStatefulPart_FileContentMismatch()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyPart.PrivateStateful, [1]);

        Assert.ThrowsException<ArgumentException>(() =>
        {
            stateManager.StoreStatefulPart([2], [3]);
        });
    }

    [TestMethod]
    public void Load()
    {
        using var directory = new TemporaryDirectory(TestContext, true);
        var data = new byte[] { 1, 2, 3 };

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyPart.Public, data);

        var read = new byte[data.Length];
        stateManager.Load(XmssKeyPart.Public, read);

        CollectionAssert.AreEqual(data, read);
    }

    [TestMethod]
    public void Load_WrongSize()
    {
        using var directory = new TemporaryDirectory(TestContext, true);
        var data = new byte[] { 1, 2, 3 };

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyPart.Public, data);

        var read = new byte[data.Length - 1];
        Assert.ThrowsException<ArgumentException>(() =>
        {
            stateManager.Load(XmssKeyPart.Public, read);
        });
    }

    [TestMethod]
    public void Load_FileNotExists()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);

        Assert.ThrowsException<FileNotFoundException>(() =>
        {
            stateManager.Load(XmssKeyPart.Public, new byte[1]);
        });
    }

    [TestMethod]
    public void Load_UnknownPart()
    {
        using var directory = new TemporaryDirectory(TestContext, true);
        var data = new byte[] { 1, 2, 3 };

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);

        Assert.ThrowsException<ArgumentOutOfRangeException>(() =>
        {
            stateManager.Load(Enum.GetValues<XmssKeyPart>().Max() + 1, new byte[1]);
        });
    }

    [TestMethod]
    public void DeletePublicPart()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyPart.Public, [1]);

        Assert.IsTrue(Directory.EnumerateFiles(directory.AbsolutePath).Any());

        stateManager.DeletePublicPart();

        Assert.IsFalse(Directory.EnumerateFiles(directory.AbsolutePath).Any());
    }

    [TestMethod]
    public void DeletePublicPart_FileNotExists()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);

        Assert.IsFalse(Directory.EnumerateFiles(directory.AbsolutePath).Any());

        stateManager.DeletePublicPart();
    }

    [TestMethod]
    public void DeletePublicPart_DirectoryNotExists()
    {
        using var directory = new TemporaryDirectory(TestContext, false);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);

        Assert.ThrowsException<DirectoryNotFoundException>(() =>
        {
            _ = Directory.EnumerateFiles(directory.AbsolutePath).Any();
        });

        Assert.ThrowsException<DirectoryNotFoundException>(() =>
        {
            stateManager.DeletePublicPart();
        });
    }

    [TestMethod]
    public void DeleteAll()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyPart.PrivateStateless, [1]);
        stateManager.Store(XmssKeyPart.PrivateStateful, [2]);
        stateManager.Store(XmssKeyPart.Public, [3]);

        Assert.IsTrue(Directory.EnumerateFiles(directory.AbsolutePath).Any());

        stateManager.DeleteAll();

        Assert.IsFalse(Directory.EnumerateFiles(directory.AbsolutePath).Any());
    }

    [TestMethod]
    public void DeleteAll_FilesNotExist()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);

        Assert.IsFalse(Directory.EnumerateFiles(directory.AbsolutePath).Any());

        stateManager.DeleteAll();
    }

    [TestMethod]
    public void DeleteAll_DirectoryNotExists()
    {
        using var directory = new TemporaryDirectory(TestContext, false);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);

        Assert.ThrowsException<DirectoryNotFoundException>(() =>
        {
            _ = Directory.EnumerateFiles(directory.AbsolutePath).Any();
        });

        Assert.ThrowsException<DirectoryNotFoundException>(() =>
        {
            stateManager.DeleteAll();
        });
    }
}
