package com.danubetech.keyformats.crypto.impl;

import bbs.signatures.Bbs;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;

import java.security.GeneralSecurityException;
import java.util.List;

public class BBSPlus_PublicKeyVerifier extends PublicKeyVerifier<byte[]> {

    public BBSPlus_PublicKeyVerifier(byte[] publicKey) {
        super(publicKey, JWSAlgorithm.BBSPlus);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {
        return verify(List.of(content), signature);
    }

    public final boolean verify(List<byte[]> content, byte[] signature, String algorithm) throws GeneralSecurityException {
        if (!algorithm.equals(getAlgorithm())) {
            throw new GeneralSecurityException("Unexpected algorithm " + algorithm + " is different from " + getAlgorithm());
        }
        return this.verify(content, signature);
    }

    public boolean verify(List<byte[]> content, byte[] signature) throws GeneralSecurityException {
        try {
            return Bbs.blsVerify(getPublicKey(), signature, content.toArray(new byte[content.size()][]));
        } catch (GeneralSecurityException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }

}
