package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.miketwk.schnorr.core.Schnorr;
import org.bitcoinj.crypto.ECKey;

import java.security.GeneralSecurityException;

public class secp256k1_ES256KS_PublicKeyVerifier extends PublicKeyVerifier<ECKey> {

    public secp256k1_ES256KS_PublicKeyVerifier(ECKey publicKey) {

        super(publicKey, JWSAlgorithm.ES256KS);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        // verify

        byte[] hash = Schnorr.sha256(content);
        boolean verified = Schnorr.schnorr_verify(hash, this.getPublicKey().getPubKey(), signature);

        // done

        return verified;
    }
}
