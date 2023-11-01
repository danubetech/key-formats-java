package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;

public class Bls12381G1_BBSPlus_PublicKeyVerifier extends BBSPlus_PublicKeyVerifier {

    public Bls12381G1_BBSPlus_PublicKeyVerifier(byte[] publicKey) {
        super(publicKey);
        int keySize = Bbs.getBls12381G1PublicKeySize();
        if (publicKey.length != keySize) {
            throw new IllegalArgumentException("wrong key size: expected: " + keySize + "but was " + publicKey.length);
        }
    }
}
