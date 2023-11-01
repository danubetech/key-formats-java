package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import bbs.signatures.KeyPair;
import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;

public class Bls12381G1_BBSPlus_PrivateKeySigner extends BBSPlus_PrivateKeySigner {

    public Bls12381G1_BBSPlus_PrivateKeySigner(KeyPair keyPair) {
        super(keyPair);
    }
}
