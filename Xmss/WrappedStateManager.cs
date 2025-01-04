// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

sealed class WrappedStateManager(IXmssStateManager? stateManager)
    : IXmssStateManager
{
    readonly IXmssStateManager? StateManager = stateManager;

    public void Store(XmssKeyPart part, ReadOnlySpan<byte> data)
    {
        if (StateManager is null)
        {
            // ephemeral key
            return;
        }
        try
        {
            StateManager.Store(part, data);
        }
        catch (Exception ex)
        {
            throw new XmssStateManagerException($"Failed storing part: {part}.", ex);
        }
    }

    public void StoreStatefulPart(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> data)
    {
        if (StateManager is null)
        {
            // ephemeral key
            return;
        }
        try
        {
            StateManager.StoreStatefulPart(expected, data);
        }
        catch (Exception ex)
        {
            throw new XmssStateManagerException("Failed uploading private stateful part.", ex);
        }
    }

    public void Load(XmssKeyPart part, Span<byte> destination)
    {
        try
        {
            if (StateManager is null)
            {
                // ephemeral key
                throw new NotImplementedException();
            }
            StateManager.Load(part, destination);
        }
        catch (Exception ex)
        {
            throw new XmssStateManagerException($"Failed loading part: {part}.", ex);
        }
    }

    public void DeletePublicPart()
    {
        if (StateManager is null)
        {
            // ephemeral key
            return;
        }
        try
        {
            StateManager.DeletePublicPart();
        }
        catch (Exception ex)
        {
            throw new XmssStateManagerException("Failed deleting public part", ex);
        }
    }

    public void Purge()
    {
        if (StateManager is null)
        {
            // ephemeral key
            return;
        }
        try
        {
            StateManager.Purge();
        }
        catch (Exception ex)
        {
            throw new XmssStateManagerException("Failed deleting parts.", ex);
        }
    }

    public void PurgeAfterFailure(Exception exception)
    {
        try
        {
            Purge();
        }
        catch (XmssStateManagerException ex2)
        {
            throw new AggregateException(exception, ex2);
        }
    }

    public void ThrowIfEphemeralKey()
    {
        if (StateManager is null)
        {
            throw new InvalidOperationException("Ephemeral keys do not support partitioning.");
        }
    }
}
