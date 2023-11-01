package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import bbs.signatures.KeyPair;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;

public class Bls12381G2_BBSPlus_PublicKeyVerifier extends BBSPlus_PublicKeyVerifier {
    public Bls12381G2_BBSPlus_PublicKeyVerifier(byte[] publicKey) {
        super(publicKey);
        int keySize = Bbs.getBls12381G2PublicKeySize();
        if (publicKey.length != keySize) {
            throw new IllegalArgumentException("wrong key size: expected: " + keySize + "but was " + publicKey.length);
        }
    }
}
