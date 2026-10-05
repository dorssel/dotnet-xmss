// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography;

namespace UnitTests;

[TestClass]
sealed class CalculateTests
{
    /// <summary>
    /// We only test XMSS_SHA2_10_256, because full calculation is very time consuming.
    /// </summary>
    [TestMethod]
    public async Task CalculatePublicKeyAsync_SingleThreadedWasm_Full()
    {
        using var xmss = new Xmss(true);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.GeneratePrivateKey(null, XmssParameterSet.XMSS_SHA2_10_256, false);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        await xmss.CalculatePublicKeyAsync((p) => { }, CancellationToken.None);

        Assert.IsTrue(xmss.HasPublicKey);
    }

    /// <summary>
    /// We only test XMSS_SHA2_10_256, because full calculation is very time consuming.
    /// </summary>
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(1022)]
    [DataRow(1023)]
    [TestMethod]
    public async Task CalculatePublicKeyAsync_FailPart(int failingPartIndex)
    {
        using var xmss = new Xmss(true, failingPartIndex);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.GeneratePrivateKey(null, XmssParameterSet.XMSS_SHA2_10_256, false);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        await Assert.ThrowsAsync<XmssException>(async () =>
        {
            await xmss.CalculatePublicKeyAsync((p) => { }, CancellationToken.None);
        });

        Assert.IsFalse(xmss.HasPublicKey);
    }

    static IEnumerable<(XmssParameterSet, bool)> GetCalculationTestData()
    {
        foreach (var parameterSet in Enum.GetValues<XmssParameterSet>())
        {
            if (parameterSet == XmssParameterSet.None)
            {
                continue;
            }
            yield return (parameterSet, false);
            yield return (parameterSet, true);
        }
    }

    /// <summary>
    /// Here we test all parameters, both for single-threaded WASM (simulated) as well as multi-threaded.
    /// We cancel before the full operation completes, though, because full calculation is very time consuming.
    /// </summary>
    [DynamicData(nameof(GetCalculationTestData))]
    [TestMethod]
    public async Task CalculatePublicKeyAsync_Cancel(XmssParameterSet parameterSet, bool testSingleThreadedWasm)
    {
        using var xmss = new Xmss(testSingleThreadedWasm);

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.GeneratePrivateKey(null, parameterSet, true);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        using var cancellationTokenSource = new CancellationTokenSource();
        await Assert.ThrowsAsync<OperationCanceledException>(async () =>
        {
            await xmss.CalculatePublicKeyAsync((p) =>
            {
                cancellationTokenSource.Cancel();
            }, cancellationTokenSource.Token);
        });

        Assert.IsFalse(xmss.HasPublicKey);
    }

    [TestMethod]
    public async Task CalculatePublicKeyAsync_Ephemeral_AndSign()
    {
        using var xmss = new Xmss();

        Assert.IsFalse(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        xmss.GeneratePrivateKey(null, XmssParameterSet.XMSS_SHA2_10_256, true);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsFalse(xmss.HasPublicKey);

        await xmss.CalculatePublicKeyAsync(null, CancellationToken.None);

        Assert.IsTrue(xmss.HasPrivateKey);
        Assert.IsTrue(xmss.HasPublicKey);

        _ = xmss.Sign([1, 2, 3]);
    }

    [TestMethod]
    public async Task CalculatePublicKeyAsync_AndImport()
    {
        var stateManager = new MockStateManager();

        // generate
        {
            using var xmss = new Xmss();

            Assert.IsFalse(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, true);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            await xmss.CalculatePublicKeyAsync(null, CancellationToken.None);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsTrue(xmss.HasPublicKey);
        }

        // import
        {
            using var xmss = new Xmss();

            Assert.IsFalse(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            xmss.ImportPrivateKey(stateManager);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsTrue(xmss.HasPublicKey);
        }
    }

    [TestMethod]
    public async Task CalculatePublicKeyAsync_Report_AndGenerateAgain()
    {
        var stateManager = new MockStateManager();

        // generate
        {
            using var xmss = new Xmss();

            Assert.IsFalse(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, true);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            var lastPercentage = 0.0;
            await xmss.CalculatePublicKeyAsync((percentage) =>
            {
                Assert.IsGreaterThan(lastPercentage, percentage);
                lastPercentage = percentage;
            }, CancellationToken.None);
            Assert.AreEqual(100.0, lastPercentage);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsTrue(xmss.HasPublicKey);

            await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            {
                await xmss.CalculatePublicKeyAsync(null, CancellationToken.None);
            });
        }
    }

    [TestMethod]
    public async Task CalculatePublicKeyAsync_DeletePublicFails()
    {
        var stateManager = new MockStateManager();

        // generate
        {
            using var xmss = new Xmss();

            Assert.IsFalse(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            xmss.GeneratePrivateKey(stateManager, XmssParameterSet.XMSS_SHA2_10_256, true);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            stateManager.Setup(false);  // DeletePublicPart

            await Assert.ThrowsExactlyAsync<XmssStateManagerException>(async () =>
            {
                await xmss.CalculatePublicKeyAsync(null, CancellationToken.None);
            });

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsTrue(xmss.HasPublicKey);
        }

        // import
        {
            using var xmss = new Xmss();

            Assert.IsFalse(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);

            xmss.ImportPrivateKey(stateManager);

            Assert.IsTrue(xmss.HasPrivateKey);
            Assert.IsFalse(xmss.HasPublicKey);
        }
    }
}
