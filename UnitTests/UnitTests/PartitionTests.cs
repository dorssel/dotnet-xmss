// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
[DoNotParallelize]
sealed class PartitionTests
{
    static readonly Xmss SharedXmss = new();

    [ClassInitialize]
    public static async Task ClassInitialize(TestContext testContext)
    {
        _ = testContext;

        SharedXmss.GeneratePrivateKey(new MockStateManager(), XmssParameterSet.XMSS_SHA2_10_256, true);
        await SharedXmss.CalculatePublicKeyAsync();
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        SharedXmss.Dispose();
    }

    [TestMethod]
    public void SplitPrivateKey()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);
        var oldRemaining = xmss.SignaturesRemaining;

        var newPartition = new MockStateManager();

        xmss.SplitPrivateKey(newPartition, 100);

        using var otherXmss = new Xmss();
        otherXmss.ImportPrivateKey(newPartition);

        Assert.AreEqual(100, otherXmss.SignaturesRemaining);
        Assert.AreEqual(oldRemaining - 100, xmss.SignaturesRemaining);
    }

    [TestMethod]
    public void SplitPrivateKey_Ephemeral()
    {
        using var xmss = new Xmss();
        xmss.GeneratePrivateKey(null, XmssParameterSet.XMSS_SHA2_10_256, false);

        Assert.ThrowsExactly<InvalidOperationException>(() =>
        {
            xmss.SplitPrivateKey(new MockStateManager(), 100);
        });
    }

    [TestMethod]
    public void SplitPrivateKey_WithPublic()
    {
        var newPartition = new MockStateManager();
        var oldRemaining = SharedXmss.SignaturesRemaining;

        SharedXmss.SplitPrivateKey(newPartition, 100);

        using var otherXmss = new Xmss();
        otherXmss.ImportPrivateKey(newPartition);

        Assert.AreEqual(100, otherXmss.SignaturesRemaining);
        Assert.AreEqual(oldRemaining - 100, SharedXmss.SignaturesRemaining);
        Assert.IsTrue(otherXmss.HasPublicKey);
    }

    [TestMethod]
    public void SplitPrivateKey_StatelessExists()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        var newPartition = new MockStateManager();
        newPartition.Store(XmssKeyPart.PrivateStateless, stateManager.GetPartData(XmssKeyPart.PrivateStateless));

        Assert.ThrowsExactly<XmssStateManagerException>(() =>
        {
            xmss.SplitPrivateKey(newPartition, 100);
        });
    }

    [TestMethod]
    public void SplitPrivateKey_StatefulExists()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        var newPartition = new MockStateManager();
        newPartition.Store(XmssKeyPart.PrivateStateful, stateManager.GetPartData(XmssKeyPart.PrivateStateful));

        Assert.ThrowsExactly<XmssStateManagerException>(() =>
        {
            xmss.SplitPrivateKey(newPartition, 100);
        });
    }

    [TestMethod]
    public void SplitPrivateKey_CleanupFails()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        var newPartition = new MockStateManager();
        newPartition.Setup();       // Load stateful
        newPartition.Setup();       // Load stateless
        newPartition.Setup(false);  // Purge

        Assert.ThrowsExactly<XmssStateManagerException>(() =>
        {
            xmss.SplitPrivateKey(newPartition, 100);
        });
    }

    [TestMethod]
    public void SplitPrivateKey_CopyStatelessFails()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        var newPartition = new MockStateManager();
        newPartition.Setup();       // Load stateful
        newPartition.Setup();       // Load stateless
        newPartition.Setup();       // Purge
        newPartition.Setup(false);  // Store stateless

        Assert.ThrowsExactly<XmssStateManagerException>(() =>
        {
            xmss.SplitPrivateKey(newPartition, 100);
        });
    }

    [TestMethod]
    public void SplitPrivateKey_CopyStatelessAndRollbackFail()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        var newPartition = new MockStateManager();
        newPartition.Setup();       // Load stateful
        newPartition.Setup();       // Load stateless
        newPartition.Setup();       // Purge
        newPartition.Setup(false);  // Store stateless
        newPartition.Setup(false);  // Purge

        Assert.ThrowsExactly<AggregateException>(() =>
        {
            xmss.SplitPrivateKey(newPartition, 100);
        });
    }

    [TestMethod]
    public void SplitPrivateKey_CopyPublicFails()
    {
        var newPartition = new MockStateManager();
        newPartition.Setup();       // Load stateful
        newPartition.Setup();       // Load stateless
        newPartition.Setup();       // Purge
        newPartition.Setup();       // Store stateless
        newPartition.Setup(false);  // Store public

        Assert.ThrowsExactly<XmssStateManagerException>(() =>
        {
            SharedXmss.SplitPrivateKey(newPartition, 100);
        });
    }

    [TestMethod]
    public void SplitPrivateKey_CopyPublicAndRollbackFail()
    {
        var newPartition = new MockStateManager();
        newPartition.Setup();       // Load stateful
        newPartition.Setup();       // Load stateless
        newPartition.Setup();       // Purge
        newPartition.Setup();       // Store stateless
        newPartition.Setup(false);  // Store public
        newPartition.Setup(false);  // Purge

        Assert.ThrowsExactly<AggregateException>(() =>
        {
            SharedXmss.SplitPrivateKey(newPartition, 100);
        });
    }

    [TestMethod]
    public void SplitPrivateKey_SplitFails()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        var newPartition = new MockStateManager();

        Assert.ThrowsExactly<XmssException>(() =>
        {
            xmss.SplitPrivateKey(newPartition, 9999);
        });
    }

    [TestMethod]
    public void SplitPrivateKey_SplitAndRollbackFail()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        var newPartition = new MockStateManager();
        newPartition.Setup();       // Load stateful
        newPartition.Setup();       // Load stateless
        newPartition.Setup();       // Purge
        newPartition.Setup();       // Store stateless
        newPartition.Setup(false);  // Purge

        Assert.ThrowsExactly<AggregateException>(() =>
        {
            xmss.SplitPrivateKey(newPartition, 9999);
        });
    }

    [TestMethod]
    public void SplitPrivateKey_UpdateStatefulFails()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        var newPartition = new MockStateManager();

        // corrupt stateful part
        Array.Clear(stateManager.GetPartData(XmssKeyPart.PrivateStateful)!);

        Assert.ThrowsExactly<XmssStateManagerException>(() =>
        {
            xmss.SplitPrivateKey(newPartition, 100);
        });
        Assert.IsFalse(xmss.HasPrivateKey);
    }

    [TestMethod]
    public void SplitPrivateKey_UpdateStatefulAndRollbackFail()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        var newPartition = new MockStateManager();
        newPartition.Setup();       // Load stateful
        newPartition.Setup();       // Load stateless
        newPartition.Setup();       // Purge
        newPartition.Setup();       // Store stateless
        newPartition.Setup(false);  // Purge

        // corrupt stateful part
        Array.Clear(stateManager.GetPartData(XmssKeyPart.PrivateStateful)!);

        Assert.ThrowsExactly<AggregateException>(() =>
        {
            xmss.SplitPrivateKey(newPartition, 100);
        });
        Assert.IsFalse(xmss.HasPrivateKey);
    }

    [TestMethod]
    public void SplitPrivateKey_StoreStatefulFails()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        var newPartition = new MockStateManager();
        newPartition.Setup();       // Load stateful
        newPartition.Setup();       // Load stateless
        newPartition.Setup();       // Purge
        newPartition.Setup();       // Store stateless
        newPartition.Setup(false);  // Store stateful

        Assert.ThrowsExactly<XmssStateManagerException>(() =>
        {
            xmss.SplitPrivateKey(newPartition, 100);
        });
    }

    [TestMethod]
    public void SplitPrivateKey_StoreStatefulAndRollbackFail()
    {
        using var xmss = new Xmss();
        var stateManager = new MockStateManager();
        xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);

        var newPartition = new MockStateManager();
        newPartition.Setup();       // Load stateful
        newPartition.Setup();       // Load stateless
        newPartition.Setup();       // Purge
        newPartition.Setup();       // Store stateless
        newPartition.Setup(false);  // Store stateful
        newPartition.Setup(false);  // Purge

        Assert.ThrowsExactly<AggregateException>(() =>
        {
            xmss.SplitPrivateKey(newPartition, 100);
        });
    }

    [TestMethod]
    public void MergePartition()
    {
        var partition1 = new MockStateManager();
        var partition2 = new MockStateManager();
        int oldRemaining;

        {
            using var tmpXmss = new Xmss();
            tmpXmss.GeneratePrivateKey(partition1, XmssParameterSet.XMSS_SHA2_10_256, false);
            var otherPartition = new MockStateManager();
            tmpXmss.SplitPrivateKey(partition2, 100);
            oldRemaining = tmpXmss.SignaturesRemaining;
        }

        using var xmss = new Xmss();
        xmss.ImportPrivateKey(partition1);
        xmss.MergePartition(partition2);

        Assert.AreEqual(oldRemaining + 100, xmss.SignaturesRemaining);
        {
            using var otherXmss = new Xmss();
            Assert.ThrowsExactly<XmssStateManagerException>(() =>
            {
                otherXmss.ImportPrivateKey(partition2);
            });
        }
    }

    [TestMethod]
    public void MergePartition_Ephemeral()
    {
        var stateManager = new MockStateManager();
        {
            using var tmpXmss = new Xmss();
            tmpXmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, false);
        }

        using var xmss = new Xmss();
        xmss.GeneratePrivateKey(null, XmssParameterSet.XMSS_SHA2_10_256, false);

        Assert.ThrowsExactly<InvalidOperationException>(() =>
        {
            xmss.MergePartition(stateManager);
        });
    }

    [TestMethod]
    public void MergePartition_DeleteFails()
    {
        var partition1 = new MockStateManager();
        var partition2 = new MockStateManager();
        int oldRemaining;

        {
            using var tmpXmss = new Xmss();
            tmpXmss.GeneratePrivateKey(partition1, XmssParameterSet.XMSS_SHA2_10_256, false);
            var otherPartition = new MockStateManager();
            tmpXmss.SplitPrivateKey(partition2, 100);
            oldRemaining = tmpXmss.SignaturesRemaining;
        }

        using var xmss = new Xmss();
        xmss.ImportPrivateKey(partition1);

        partition2.Setup();         // Load stateful
        partition2.Setup(false);    // Purge

        Assert.ThrowsExactly<XmssStateManagerException>(() =>
        {
            xmss.MergePartition(partition2);
        });
        Assert.IsFalse(xmss.HasPrivateKey);
    }
}
