package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import bbs.signatures.KeyPair;
import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;
import java.util.List;

public class BBSPlus_PrivateKeySigner extends PrivateKeySigner<byte[]> {

    private final byte[] publicKey;

    public BBSPlus_PrivateKeySigner(KeyPair keyPair) {
        super( keyPair.secretKey, JWSAlgorithm.BBSPlus);
        int keySize = Bbs.getSecretKeySize();
        if (keyPair.secretKey.length != keySize) {
            throw new IllegalArgumentException("wrong key size: expected: " + keySize + "but was " + keyPair.secretKey.length);
        }
        publicKey = keyPair.publicKey;
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {
        return sign(List.of(content));
    }

    public final byte[] sign(List<byte[]> content, String algorithm) throws GeneralSecurityException {

        if (! algorithm.equals(getAlgorithm())) throw new GeneralSecurityException("Unexpected algorithm " + algorithm + " is different from " + getAlgorithm());

        return this.sign(content);
    }

    public byte[] sign(List<byte[]> content) throws GeneralSecurityException {
        try {
            return Bbs.blsSign(getPrivateKey(), publicKey, content.toArray(new byte[content.size()][]));
        } catch (GeneralSecurityException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
