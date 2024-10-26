// SPDX-FileCopyrightText: 2024 Frans van Dorsselaer
//
// SPDX-License-Identifier: MIT

using Dorssel.Security.Cryptography.Internal;

namespace UnitTests;

[TestClass]
sealed unsafe class StructuresTests
{
    [TestMethod]
    public void XmssPrivateKeyStatelessBlob_data()
    {
        XmssPrivateKeyStatelessBlob privateKeyStatelessBlob = default;
        Assert.IsFalse(privateKeyStatelessBlob.data == null);
    }

    [TestMethod]
    public void XmssPrivateKeyStatefulBlob_data()
    {
        XmssPrivateKeyStatefulBlob privateKeyStatefulBlob = default;
        Assert.IsFalse(privateKeyStatefulBlob.data == null);
    }

    [TestMethod]
    public void XmssPublicKeyInternalBlob_data()
    {
        XmssPublicKeyInternalBlob publicKeyInternalBlob = default;
        Assert.IsFalse(publicKeyInternalBlob.data == null);
    }

    [TestMethod]
    public void XMSS_PUBLIC_KEY_SIZE()
    {
        _ = Defines.XMSS_PUBLIC_KEY_SIZE;
    }

    [TestMethod]
    public void XmssSignature_authentication_path()
    {
        XmssSignature signature = default;
        Assert.IsFalse(signature.authentication_path == null);
    }

    [TestMethod]
    public void XmssSignatureBlob_data()
    {
        XmssSignatureBlob signatureBlob = default;
        Assert.IsFalse(signatureBlob.data == null);
    }

    [TestMethod]
    public void xmss_get_signature_struct()
    {
        XmssSignatureBlob signatureBlob;
        Assert.IsFalse(UnsafeNativeMethods.xmss_get_signature_struct(&signatureBlob) == null);
    }

    [TestMethod]
    public void xmss_get_signature_struct_Null()
    {
        Assert.IsTrue(UnsafeNativeMethods.xmss_get_signature_struct(null) == null);
    }

    [TestMethod]
    public void xmss_error_to_description()
    {
        foreach (var error in Enum.GetValues<XmssError>())
        {
            Assert.IsFalse(string.IsNullOrEmpty(UnsafeNativeMethods.xmss_error_to_description(error)));
        }
    }
}
