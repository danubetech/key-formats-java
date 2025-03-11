package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoin.NativeSecp256k1;
import org.bitcoin.NativeSecp256k1Util;
import org.bitcoinj.crypto.ECKey;

import java.security.GeneralSecurityException;
import java.util.Arrays;

public class secp256k1_ES256KS_PublicKeyVerifier extends PublicKeyVerifier<ECKey> {

    public secp256k1_ES256KS_PublicKeyVerifier(ECKey publicKey) {

        super(publicKey, JWSAlgorithm.ES256KS);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        boolean verified;

            // verify

        byte[] hash = SHA256Provider.get().sha256(content);
        byte[] publicKey = Arrays.copyOfRange(this.getPublicKey().getPubKey(), 1, this.getPublicKey().getPubKey().length);
        try {
            verified = NativeSecp256k1.schnorrVerify(signature, hash, publicKey);
        } catch (NativeSecp256k1Util.AssertFailException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }

        // done

        return verified;
    }
}
