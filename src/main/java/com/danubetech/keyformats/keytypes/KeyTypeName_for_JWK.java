package com.danubetech.keyformats.keytypes;

import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import com.danubetech.keyformats.jose.KeyTypeName;

public class KeyTypeName_for_JWK {

	public static KeyTypeName keyTypeName_for_JWK(JWK jwk) {

		if (jwk.getKty() == null) throw new IllegalArgumentException("No 'kty' found in JWK.");
		if (KeyType.RSA.equals(jwk.getKty()))
			return KeyTypeName.from(jwk.getKty());	// "RSA"
		else if (KeyType.EC.equals(jwk.getKty()))
			return KeyTypeName.from(jwk.getCrv());	// "secp256k1"
		else if (KeyType.OKP.equals(jwk.getKty()))
			return KeyTypeName.from(jwk.getCrv());	// "Ed25519", "X25519", "Bls12381G1", "Bls12381G2", "Bls48581G1", "Bls48581G2"
		else
			throw new IllegalArgumentException("Unsupported key type " + jwk.getKty());
	}
}
