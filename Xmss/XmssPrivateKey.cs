// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.InteropServices;

namespace Dorssel.Security.Cryptography;

sealed class XmssPrivateKey(StateManagerWrapper wrappedStateManager) : IDisposable
{
    readonly StateManagerWrapper _WrappedStateManager = wrappedStateManager;
    readonly CriticalXmssKeyContextHandle _KeyContext = new();
    readonly CriticalXmssPrivateKeyStatefulBlobHandle _StatefulBlob = new();

    public IXmssStateManager WrappedStateManager
    {
        get
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            return _WrappedStateManager;
        }
    }

    public CriticalXmssKeyContextHandle KeyContext
    {
        get
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            return _KeyContext;
        }
    }

    public CriticalXmssPrivateKeyStatefulBlobHandle StatefulBlob
    {
        get
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            return _StatefulBlob;
        }
    }

    bool IsDisposed;

    public void Dispose()
    {
        if (!IsDisposed)
        {
            _KeyContext.Dispose();
            _StatefulBlob.Dispose();
            IsDisposed = true;
        }
    }
}
