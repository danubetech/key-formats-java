package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.miketwk.schnorr.core.Schnorr;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.LazyECPoint;

import java.security.GeneralSecurityException;

public class secp256k1_ES256KS_PublicKeyVerifier extends PublicKeyVerifier<ECKey> {

    public secp256k1_ES256KS_PublicKeyVerifier(ECKey publicKey) {

        super(publicKey, JWSAlgorithm.ES256KS);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        // verify

        byte[] hash = Schnorr.sha256(content);
        ECKey compressedPublicKey = ECKey.fromPublicOnly(new LazyECPoint(this.getPublicKey().getPubKeyPoint(), true).get(), true);
        boolean verified = Schnorr.schnorr_verify(hash, compressedPublicKey.getPubKey(), signature);

        // done

        return verified;
    }
}
