package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;

public class Ed25519_EdDSA_PrivateKeySigner extends PrivateKeySigner<byte[]> {

    public Ed25519_EdDSA_PrivateKeySigner(byte[] privateKey) {

        super(privateKey, JWSAlgorithm.EdDSA);

        if (privateKey.length != 64) throw new IllegalArgumentException("Expected 32 bytes instead of " + privateKey.length);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        return Ed25519Provider.get().sign(content, this.getPrivateKey());
    }
}
