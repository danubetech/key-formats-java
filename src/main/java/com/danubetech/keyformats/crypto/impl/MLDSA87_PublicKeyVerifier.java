package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.MLDSASigner;

import java.security.GeneralSecurityException;

public class MLDSA87_PublicKeyVerifier extends PublicKeyVerifier<MLDSAPublicKeyParameters> {

    public MLDSA87_PublicKeyVerifier(MLDSAPublicKeyParameters publicKey) {

        super(publicKey, JWSAlgorithm.ML_DSA_87);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        MLDSASigner verifier = new MLDSASigner();
        verifier.init(false, this.getPublicKey());
        verifier.update(content, 0, content.length);

        return verifier.verifySignature(signature);
    }
}
