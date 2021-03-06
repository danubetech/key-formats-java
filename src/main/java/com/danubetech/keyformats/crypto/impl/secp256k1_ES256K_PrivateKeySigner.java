package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;

import java.security.GeneralSecurityException;

public class secp256k1_ES256K_PrivateKeySigner extends PrivateKeySigner<ECKey> {

    public secp256k1_ES256K_PrivateKeySigner(ECKey privateKey) {

        super(privateKey, JWSAlgorithm.ES256K);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        return this.getPrivateKey().sign(Sha256Hash.of(content)).encodeToDER();
    }
}
