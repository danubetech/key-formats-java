package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PrivateKeySigner;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.fasterxml.jackson.databind.json.JsonMapper;
import fr.acinq.bitcoin.*;
import fr.acinq.bitcoin.crypto.musig2.IndividualNonce;
import fr.acinq.bitcoin.crypto.musig2.Musig2;
import fr.acinq.bitcoin.crypto.musig2.SecretNonce;
import fr.acinq.bitcoin.crypto.musig2.Session;
import fr.acinq.bitcoin.utils.Either;
import org.bitcoinj.crypto.ECKey;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.List;
import java.util.Map;

public class secp256k1_MUSIG2_PrivateKeySigner extends PrivateKeySigner<ECKey> {

    private static final JsonMapper jsonMapper = JsonMapper.builder().build();

    public secp256k1_MUSIG2_PrivateKeySigner(ECKey privateKey) {

        super(privateKey, JWSAlgorithm.MUSIG2);
    }

    @Override
    public byte[] sign(byte[] content) throws GeneralSecurityException {

        byte[] signatureBytes;

        // decode

        Map<String, Object> contentMap = null;
        try {
            contentMap = jsonMapper.readValue(content, Map.class);
        } catch (IOException ex) {
            throw new GeneralSecurityException("Cannot parse payload for MuSig2 signature: " + ex.getMessage(), ex);
        }

        if (! contentMap.containsKey("tx")) throw new GeneralSecurityException("Missing 'tx' in payload for MuSig2 signature");
        if (! contentMap.containsKey("inputIndex")) throw new GeneralSecurityException("Missing 'inputIndex' in payload for MuSig2 signature");
        if (! contentMap.containsKey("inputs")) throw new GeneralSecurityException("Missing 'inputs' in payload for MuSig2 signature");
        if (! contentMap.containsKey("publicKeys")) throw new GeneralSecurityException("Missing 'publicKeys' in payload for MuSig2 signature");
        if (! contentMap.containsKey("secretNonce")) throw new GeneralSecurityException("Missing 'secretNonce' in payload for MuSig2 signature");
        if (! contentMap.containsKey("publicNonces")) throw new GeneralSecurityException("Missing 'publicNonces' in payload for MuSig2 signature");

        byte[] tx = Base64.getDecoder().decode(((String) contentMap.get("tx")));
        int inputIndex = ((Number) contentMap.get("inputIndex")).intValue();
        List<byte[]> inputs = ((List<String>) contentMap.get("inputs")).stream().map(x -> Base64.getDecoder().decode(x)).toList();
        List<byte[]> publicKeys = ((List<String>) contentMap.get("publicKeys")).stream().map(x -> Base64.getDecoder().decode(x)).toList();
        byte[] secretNonce = Base64.getDecoder().decode(((String) contentMap.get("secretNonce")));
        List<byte[]> publicNonces = ((List<String>) contentMap.get("publicNonces")).stream().map(x -> Base64.getDecoder().decode(x)).toList();

        // sign

        Either<Throwable, Session> musig2Session = Musig2.taprootSession(
                Transaction.read(tx),
                inputIndex,
                inputs.stream().map(TxOut::read).toList(),
                publicKeys.stream().map(PublicKey::parse).toList(),
                publicNonces.stream().map(IndividualNonce::new).toList(),
                null
        );
        if (musig2Session.isLeft()) throw new GeneralSecurityException("Cannot create MuSig2 session: " + musig2Session.getLeft().getMessage(), musig2Session.getLeft());
        if (! musig2Session.isRight()) throw new IllegalStateException("Invalid MuSig2 session: " + musig2Session);

        ByteVector32 musig2Signature = null;
        try {
            musig2Signature = musig2Session.getRight().sign(
                    new SecretNonce(secretNonce),
                    new PrivateKey(this.getPrivateKey().getPrivKeyBytes())
            );
        } catch (Exception ex) {
            throw new GeneralSecurityException("Cannot create MuSig2 signature: " + ex.getMessage(), ex);
        }
        if (musig2Signature == null) throw new GeneralSecurityException("Invalid MuSig2 signature: " + musig2Signature);

        signatureBytes = musig2Signature.toByteArray();

        // done

        return signatureBytes;
    }
}
