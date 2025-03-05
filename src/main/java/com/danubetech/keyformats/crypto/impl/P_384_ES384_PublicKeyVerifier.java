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

public class P_384_ES384_PublicKeyVerifier extends PublicKeyVerifier<ECPublicKey> {

    public P_384_ES384_PublicKeyVerifier(ECPublicKey publicKey) {

        super(publicKey, JWSAlgorithm.ES384);

        byte[] point = EC5Util.convertPoint(publicKey.getParams(), publicKey.getW()).getEncoded(true);
        if (point.length != 49) throw new IllegalArgumentException("Invalid key size (not 49 bytes): " + Hex.encodeHexString(point) + ", length=" + point.length);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        Signature jcaSignature = Signature.getInstance("SHA384withECDSA");

        jcaSignature.initVerify(this.getPublicKey());
        jcaSignature.update(content);

        try {
            return jcaSignature.verify(ASNUtil.jwsSignatureToAsn1ESSignature(signature));
        } catch (IOException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
