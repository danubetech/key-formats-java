package com.danubetech.keyformats;

import java.security.interfaces.RSAPublicKey;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import org.apache.commons.codec.binary.Base64;
import org.bitcoinj.core.ECKey;
import org.bouncycastle.math.ec.ECPoint;

public class PublicKey_to_JWK {

	public static JWK RSAPublicKey_to_JWK(RSAPublicKey publicKey, String kid, String use) {

		throw new RuntimeException("Not supported");

/*		JWK jsonWebKey = new JWK();
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);

		JWK jsonWebKey = new com.nimbusds.jose.jwk.RSAKey.Builder(publicKey)
				.keyID(kid)
				.keyUse(use == null ? null : new KeyUse(use))
				.build();

		return jsonWebKey;*/
	}

	public static JWK secp256k1PublicKey_to_JWK(ECKey publicKey, String kid, String use) {

		ECPoint publicKeyPoint = publicKey.getPubKeyPoint();

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.secp256k1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyPoint.getAffineXCoord().getEncoded()));
		jsonWebKey.setY(Base64.encodeBase64URLSafeString(publicKeyPoint.getAffineYCoord().getEncoded()));

		return jsonWebKey;
	}

	public static JWK secp256k1PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		ECKey publicKey = ECKey.fromPublicOnly(publicKeyBytes);

		return secp256k1PublicKey_to_JWK(publicKey, kid, use);
	}

	public static JWK BLS12381_G1PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.BLS12381_G1);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK BLS12381_G1PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		KeyPair publicKey = new KeyPair(publicKeyBytes, null);

		return BLS12381_G1PublicKey_to_JWK(publicKey, kid, use);
	}

	public static JWK BLS12381_G2PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.EC);
		jsonWebKey.setCrv(Curve.BLS12381_G2);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK BLS12381_G2PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		KeyPair publicKey = new KeyPair(publicKeyBytes, null);

		return BLS12381_G2PublicKey_to_JWK(publicKey, kid, use);
	}

	public static JWK Ed25519PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.Ed25519);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));

		return jsonWebKey;
	}

	public static JWK X25519PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		JWK jsonWebKey = new JWK();
		jsonWebKey.setKty(KeyType.OKP);
		jsonWebKey.setCrv(Curve.X25519);
		jsonWebKey.setKid(kid);
		jsonWebKey.setUse(use);
		jsonWebKey.setX(Base64.encodeBase64URLSafeString(publicKeyBytes));

		return jsonWebKey;
	}
}
