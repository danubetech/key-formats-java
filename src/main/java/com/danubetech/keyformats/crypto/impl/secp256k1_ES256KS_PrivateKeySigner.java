package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.secp.api.P256K1KeyPair;
import org.bitcoinj.secp.api.P256k1PrivKey;
import org.bitcoinj.secp.api.Secp256k1;
import org.bitcoinj.secp.bouncy.Bouncy256k1;
import org.bitcoinj.secp.bouncy.BouncyPrivKey;

import java.security.GeneralSecurityException;

public class secp256k1_ES256KS_PrivateKeySigner extends PrivateKeySigner<ECKey> {

    public secp256k1_ES256KS_PrivateKeySigner(ECKey privateKey) {

        super(privateKey, JWSAlgorithm.ES256KS);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        byte[] signatureBytes;

        try (Secp256k1 secp256k1 = new Bouncy256k1()) {

            P256k1PrivKey p256k1PrivKey = new BouncyPrivKey(this.getPrivateKey().getPrivKey());
            P256K1KeyPair p256K1KeyPair = secp256k1.ecKeyPairCreate(p256k1PrivKey);

            // sign

            byte[] hash = SHA256Provider.get().sha256(content);
            signatureBytes = secp256k1.schnorrSigSign32(hash, p256K1KeyPair);
        }

        // done

        return signatureBytes;
    }
}
