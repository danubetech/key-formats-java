package com.danubetech.keyformats.crypto;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.keytypes.*;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignVerifyTest {

	private static final byte[] CONTENT = "Hello World!".getBytes(StandardCharsets.UTF_8);

	private static final Map<PrivateKeySigner<?>, PublicKeyVerifier<?>> SIGNERS_VERIFIERS = Map.of(
			PrivateKeySignerFactory.privateKeySignerForKey(Ed25519Test.jwkPrivate, JWSAlgorithm.EdDSA),
			PublicKeyVerifierFactory.publicKeyVerifierForKey(Ed25519Test.jwkPublic, JWSAlgorithm.EdDSA),
			PrivateKeySignerFactory.privateKeySignerForKey(secp256k1Test.jwkPrivate, JWSAlgorithm.ES256K),
			PublicKeyVerifierFactory.publicKeyVerifierForKey(secp256k1Test.jwkPublic, JWSAlgorithm.ES256K),
			PrivateKeySignerFactory.privateKeySignerForKey(secp256k1Test.jwkPrivate, JWSAlgorithm.ES256KCC),
			PublicKeyVerifierFactory.publicKeyVerifierForKey(secp256k1Test.jwkPublic, JWSAlgorithm.ES256KCC),
			PrivateKeySignerFactory.privateKeySignerForKey(secp256k1Test.jwkPrivate, JWSAlgorithm.ES256KRR),
			PublicKeyVerifierFactory.publicKeyVerifierForKey(secp256k1Test.jwkPublic, JWSAlgorithm.ES256KRR),
			//PrivateKeySignerFactory.privateKeySignerForKey(secp256k1Test.jwkPrivate, JWSAlgorithm.ES256KS),
			//PublicKeyVerifierFactory.publicKeyVerifierForKey(secp256k1Test.jwkPublic, JWSAlgorithm.ES256KS),
			PrivateKeySignerFactory.privateKeySignerForKey(P_256Test.jwkPrivate, JWSAlgorithm.ES256),
			PublicKeyVerifierFactory.publicKeyVerifierForKey(P_256Test.jwkPublic, JWSAlgorithm.ES256),
			PrivateKeySignerFactory.privateKeySignerForKey(P_384Test.jwkPrivate, JWSAlgorithm.ES384),
			PublicKeyVerifierFactory.publicKeyVerifierForKey(P_384Test.jwkPublic, JWSAlgorithm.ES384),
			PrivateKeySignerFactory.privateKeySignerForKey(P_521Test.jwkPrivate, JWSAlgorithm.ES512),
			PublicKeyVerifierFactory.publicKeyVerifierForKey(P_521Test.jwkPublic, JWSAlgorithm.ES512)
	);

	@Test
	public void testSignVerify() throws Exception {
		for (Map.Entry<PrivateKeySigner<?>, PublicKeyVerifier<?>> pair : SIGNERS_VERIFIERS.entrySet()) {
			PrivateKeySigner<?> privateKeySigner = pair.getKey();
			PublicKeyVerifier<?> publicKeyVerifierFactory = pair.getValue();
			byte[] signature = privateKeySigner.sign(CONTENT);
			assertTrue(publicKeyVerifierFactory.verify(CONTENT, signature));
		}
	}
}
