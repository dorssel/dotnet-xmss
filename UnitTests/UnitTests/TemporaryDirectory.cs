// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace UnitTests;

sealed partial class TemporaryDirectory : IDisposable
{
    static readonly Guid BaseDirectory = Guid.NewGuid();

    static long Count;

    public TemporaryDirectory(TestContext context, bool create = false)
    {
        Assert.IsNotNull(context.DeploymentDirectory);
        var name = Interlocked.Increment(ref Count);
        AbsolutePath = Path.Combine(context.DeploymentDirectory, $"{BaseDirectory}.{name}");
        if (create)
        {
            Directory.CreateDirectory(AbsolutePath);
        }
    }

    public string AbsolutePath { get; }

    public void Dispose()
    {
        if (Directory.Exists(AbsolutePath))
        {
            Directory.Delete(AbsolutePath, true);
        }
    }
}
