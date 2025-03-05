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

public class P_256_ES256_PublicKeyVerifier extends PublicKeyVerifier<ECPublicKey> {

    public P_256_ES256_PublicKeyVerifier(ECPublicKey publicKey) {

        super(publicKey, JWSAlgorithm.ES256);

        byte[] point = EC5Util.convertPoint(publicKey.getParams(), publicKey.getW()).getEncoded(true);
        if (point.length != 33) throw new IllegalArgumentException("Invalid key size (not 33 bytes): " + Hex.encodeHexString(point) + ", length=" + point.length);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        Signature jcaSignature = Signature.getInstance("SHA256withECDSA");

        jcaSignature.initVerify(this.getPublicKey());
        jcaSignature.update(content);

        try {
            return jcaSignature.verify(ASNUtil.jwsSignatureToAsn1ESSignature(signature));
        } catch (IOException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
