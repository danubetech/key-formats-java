package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoin.NativeSecp256k1;
import org.bitcoin.NativeSecp256k1Util;
import org.bitcoinj.crypto.ECKey;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Random;

public class secp256k1_ES256KS_PrivateKeySigner extends PrivateKeySigner<ECKey> {

    public secp256k1_ES256KS_PrivateKeySigner(ECKey privateKey) {

        super(privateKey, JWSAlgorithm.ES256KS);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        byte[] signatureBytes;

        // sign

        byte[] hash = SHA256Provider.get().sha256(content);
        byte[] privateKey = this.getPrivateKey().getPrivKeyBytes();
        byte[] auxRand = new byte[32];
        Arrays.fill(auxRand, (byte) 0xff);
        try {
            signatureBytes = NativeSecp256k1.schnorrSign(hash, privateKey, auxRand);
        } catch (NativeSecp256k1Util.AssertFailException ex) {
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }

        // done

        return signatureBytes;
    }
}
