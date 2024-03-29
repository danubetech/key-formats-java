package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;

public class Bls48581G1_BBSPlus_PrivateKeySigner extends PrivateKeySigner<KeyPair> {

    public Bls48581G1_BBSPlus_PrivateKeySigner(KeyPair privateKey) {

        super(privateKey, JWSAlgorithm.BBSPlus);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        throw new RuntimeException("Not implemented");
    }
}
