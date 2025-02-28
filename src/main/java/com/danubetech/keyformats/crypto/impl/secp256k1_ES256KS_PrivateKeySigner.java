package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.miketwk.schnorr.core.Schnorr;
import org.bitcoinj.crypto.ECKey;

import java.security.GeneralSecurityException;

public class secp256k1_ES256KS_PrivateKeySigner extends PrivateKeySigner<ECKey> {

    public secp256k1_ES256KS_PrivateKeySigner(ECKey privateKey) {

        super(privateKey, JWSAlgorithm.ES256KS);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        // sign

        byte[] hash = Schnorr.sha256(content);
        byte[] signatureBytes = Schnorr.schnorr_sign(hash, this.getPrivateKey().getPrivKey());

        // done

        return signatureBytes;
    }
}
