package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.secp.api.P256K1XOnlyPubKey;
import org.bitcoinj.secp.api.P256k1PubKey;
import org.bitcoinj.secp.api.Result;
import org.bitcoinj.secp.api.Secp256k1;
import org.bitcoinj.secp.bouncy.Bouncy256k1;
import org.bitcoinj.secp.bouncy.BouncyPubKey;

import java.security.GeneralSecurityException;

public class secp256k1_ES256KS_PublicKeyVerifier extends PublicKeyVerifier<ECKey> {

    public secp256k1_ES256KS_PublicKeyVerifier(ECKey publicKey) {

        super(publicKey, JWSAlgorithm.ES256KS);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        boolean verified;

        try (Secp256k1 secp256k1 = new Bouncy256k1()) {

            P256k1PubKey p256k1PubKey = new BouncyPubKey(this.getPublicKey().getPubKeyPoint());
            P256K1XOnlyPubKey p256K1XOnlyPubKey = p256k1PubKey.getXOnly();

            // verify

            byte[] hash = SHA256Provider.get().sha256(content);
            Result<Boolean> booleanResult = secp256k1.schnorrSigVerify(signature, hash, p256K1XOnlyPubKey);
            Boolean result = booleanResult == null ? null : booleanResult.get();
            verified = result == null ? false : result;
        }

        // done

        return verified;
    }
}
