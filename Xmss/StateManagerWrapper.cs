// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

namespace Dorssel.Security.Cryptography;

sealed class StateManagerWrapper(IXmssStateManager stateManager)
    : IXmssStateManager
{
    readonly IXmssStateManager StateManager = stateManager;

    public void Store(XmssKeyPart part, ReadOnlySpan<byte> data)
    {
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
            StateManager.Load(part, destination);
        }
        catch (Exception ex)
        {
            throw new XmssStateManagerException($"Failed loading part: {part}.", ex);
        }
    }

    public void DeletePublicPart()
    {
        try
        {
            StateManager.DeletePublicPart();
        }
        catch (Exception ex)
        {
            throw new XmssStateManagerException("Failed deleting public part", ex);
        }
    }

    public void DeleteAll()
    {
        try
        {
            StateManager.DeleteAll();
        }
        catch (Exception ex)
        {
            throw new XmssStateManagerException("Failed deleting parts.", ex);
        }
    }

    public void DeleteAllAfterFailure(Exception exception)
    {
        try
        {
            DeleteAll();
        }
        catch (XmssStateManagerException ex2)
        {
            throw new AggregateException(exception, ex2);
        }
    }
}
