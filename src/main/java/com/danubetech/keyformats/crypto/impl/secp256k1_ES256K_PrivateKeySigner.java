package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.crypto.ECKey;

import java.security.GeneralSecurityException;

public class secp256k1_ES256K_PrivateKeySigner extends PrivateKeySigner<ECKey> {

    public secp256k1_ES256K_PrivateKeySigner(ECKey privateKey) {

        super(privateKey, JWSAlgorithm.ES256K);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        byte[] signatureBytes = new byte[64];

        // sign

        byte[] hash = SHA256Provider.get().sha256(content);
        ECKey.ECDSASignature ecdsaSignature = this.getPrivateKey().sign(Sha256Hash.wrap(hash));
        byte[] r = ByteUtils.bigIntegerToBytes(ecdsaSignature.r, 32);
        byte[] s = ByteUtils.bigIntegerToBytes(ecdsaSignature.s, 32);
        System.arraycopy(r, 0, signatureBytes, 0, r.length);
        System.arraycopy(s, 0, signatureBytes, 32, s.length);

        // done

        return signatureBytes;
    }
}
