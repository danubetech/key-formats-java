package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.util.ASNUtil;
import com.danubetech.keyformats.util.ByteArrayUtil;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;

public class P_521_ES512_PrivateKeySigner extends PrivateKeySigner<ECPrivateKey> {

    public P_521_ES512_PrivateKeySigner(ECPrivateKey privateKey) {

        super(privateKey, JWSAlgorithm.ES512);

        byte[] s = ByteArrayUtil.bigIntegertoByteArray(privateKey.getS());
        if (s.length != 64 && s.length != 65 && s.length != 66) throw new IllegalArgumentException("Invalid key size (not 64 or 65 or 66 bytes): private key, length=" + s.length + " (" + privateKey.getS().bitLength() + " bits)");
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        Signature jcaSignature = Signature.getInstance("SHA512withECDSA");

        jcaSignature.initSign(this.getPrivateKey());
        jcaSignature.update(content);

        try {
            return ASNUtil.asn1ESSignatureToJwsSignature(jcaSignature.sign(), 132);
        } catch (IOException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
