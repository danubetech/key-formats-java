package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;

public class Bls48581G2_BBSPlus_PublicKeyVerifier extends PublicKeyVerifier<KeyPair> {

    public Bls48581G2_BBSPlus_PublicKeyVerifier(KeyPair publicKey) {

        super(publicKey, JWSAlgorithm.BBSPlus);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        throw new RuntimeException("Not implemented");
    }
}
