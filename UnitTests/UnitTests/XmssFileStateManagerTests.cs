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
    public void Load()
    {
        using var directory = new TemporaryDirectory(TestContext, true);
        var data = new byte[] { 1, 2, 3 };

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyParts.Public, [], data);

        var read = new byte[data.Length];
        stateManager.Load(XmssKeyParts.Public, read);

        CollectionAssert.AreEqual(data, read);
    }

    [TestMethod]
    public void Load_WrongSize()
    {
        using var directory = new TemporaryDirectory(TestContext, true);
        var data = new byte[] { 1, 2, 3 };

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyParts.Public, [], data);

        var read = new byte[data.Length - 1];
        Assert.ThrowsException<ArgumentException>(() =>
        {
            stateManager.Load(XmssKeyParts.Public, read);
        });
    }

    [TestMethod]
    public void SecureDelete()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyParts.PrivateStateless, [], [1]);
        stateManager.Store(XmssKeyParts.PrivateStateful, [], [2]);
        stateManager.Store(XmssKeyParts.Public, [], [3]);

        Assert.IsTrue(Directory.EnumerateFiles(directory.AbsolutePath).Any());

        stateManager.SecureDelete();

        Assert.IsFalse(Directory.EnumerateFiles(directory.AbsolutePath).Any());
    }

    [TestMethod]
    public void DeletePublicPart()
    {
        using var directory = new TemporaryDirectory(TestContext, true);

        var stateManager = new XmssFileStateManager(directory.AbsolutePath);
        stateManager.Store(XmssKeyParts.Public, [], [3]);

        Assert.IsTrue(Directory.EnumerateFiles(directory.AbsolutePath).Any());

        stateManager.DeletePublicPart();

        Assert.IsFalse(Directory.EnumerateFiles(directory.AbsolutePath).Any());
    }
}
