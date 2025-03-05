package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.util.ASNUtil;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

public class P_521_ES512_PublicKeyVerifier extends PublicKeyVerifier<ECPublicKey> {

    public P_521_ES512_PublicKeyVerifier(ECPublicKey publicKey) {

        super(publicKey, JWSAlgorithm.ES512);

        byte[] point = EC5Util.convertPoint(publicKey.getParams(), publicKey.getW()).getEncoded(true);
        if (point.length != 65 && point.length != 66 && point.length != 67) throw new IllegalArgumentException("Invalid key size (not 65 or 66 or 67 bytes): " + Hex.encodeHexString(point) + ", length=" + point.length);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        Signature jcaSignature = Signature.getInstance("SHA512withECDSA");

        jcaSignature.initVerify(this.getPublicKey());
        jcaSignature.update(content);

        try {
            return jcaSignature.verify(ASNUtil.jwsSignatureToAsn1ESSignature(signature));
        } catch (IOException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
