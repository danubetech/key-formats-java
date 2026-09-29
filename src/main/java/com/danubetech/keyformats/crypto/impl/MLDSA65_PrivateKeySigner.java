package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;

import java.security.GeneralSecurityException;

public class MLDSA65_PrivateKeySigner extends PrivateKeySigner<MLDSAPrivateKeyParameters> {

    public MLDSA65_PrivateKeySigner(MLDSAPrivateKeyParameters privateKey) {

        super(privateKey, JWSAlgorithm.ML_DSA_65);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        MLDSASigner signer = new MLDSASigner();
        signer.init(true, this.getPrivateKey());
        signer.update(content, 0, content.length);

        try {
            return signer.generateSignature();
        } catch (CryptoException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
