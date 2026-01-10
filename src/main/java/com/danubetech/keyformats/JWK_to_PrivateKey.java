package com.danubetech.keyformats;

import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import com.danubetech.keyformats.jose.KeyTypeName;
import com.danubetech.keyformats.keytypes.KeyTypeName_for_JWK;
import org.bitcoinj.crypto.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.*;

public class JWK_to_PrivateKey {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static Object JWK_to_anyPrivateKey(JWK jwk) {

		KeyTypeName keyType = KeyTypeName_for_JWK.keyTypeName_for_JWK(jwk);

		if (keyType == KeyTypeName.RSA)
			return JWK_to_RSAPrivateKey(jwk);
		else if (keyType == KeyTypeName.secp256k1)
			return JWK_to_secp256k1PrivateKey(jwk);
		else if (keyType == KeyTypeName.Bls12381G1)
			return JWK_to_Bls12381G1PrivateKey(jwk);
		else if (keyType == KeyTypeName.Bls12381G2)
			return JWK_to_Bls12381G2PrivateKey(jwk);
		else if (keyType == KeyTypeName.Bls48581G1)
			return JWK_to_Bls12381G1PrivateKey(jwk);
		else if (keyType == KeyTypeName.Bls48581G2)
			return JWK_to_Bls12381G2PrivateKey(jwk);
		else if (keyType == KeyTypeName.Ed25519)
			return JWK_to_Ed25519PrivateKey(jwk);
		else if (keyType == KeyTypeName.X25519)
			return JWK_to_X25519PrivateKey(jwk);
		else if (keyType == KeyTypeName.P_256)
			return JWK_to_P_256PrivateKey(jwk);
		else if (keyType == KeyTypeName.P_384)
			return JWK_to_P_384PrivateKey(jwk);
		else if (keyType == KeyTypeName.P_521)
			return JWK_to_P_521PrivateKey(jwk);
		else
			throw new IllegalArgumentException("Unsupported key type: " + keyType);
	}

	public static KeyPair JWK_to_RSAPrivateKey(JWK jwk) {

		if (! KeyType.RSA.equals(jwk.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jwk.getKty());

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(new BigInteger(1, jwk.getNdecoded()), new BigInteger(1, jwk.getDdecoded()));
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(new BigInteger(1, jwk.getNdecoded()), new BigInteger(1, jwk.getEdecoded()));
			return new KeyPair(keyFactory.generatePublic(rsaPublicKeySpec), keyFactory.generatePrivate(rsaPrivateKeySpec));
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}
	}

	public static ECKey JWK_to_secp256k1PrivateKey(JWK jwk) {

		if (! KeyType.EC.equals(jwk.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jwk.getKty());
		if (! Curve.secp256k1.equals(jwk.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jwk.getCrv());

		return ECKey.fromPrivate(jwk.getDdecoded());
	}

	public static bbs.signatures.KeyPair JWK_to_Bls12381G1PrivateKey(JWK jwk) {

		if (! KeyType.OKP.equals(jwk.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jwk.getKty());
		if (! Curve.Bls12381G1.equals(jwk.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jwk.getCrv());

		return new bbs.signatures.KeyPair(jwk.getXdecoded(), jwk.getDdecoded());
	}

	public static bbs.signatures.KeyPair JWK_to_Bls12381G2PrivateKey(JWK jwk) {

		if (! KeyType.OKP.equals(jwk.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jwk.getKty());
		if (! Curve.Bls12381G2.equals(jwk.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jwk.getCrv());

		return new bbs.signatures.KeyPair(jwk.getXdecoded(), jwk.getDdecoded());
	}

	public static bbs.signatures.KeyPair JWK_to_Bls48581G1PrivateKey(JWK jwk) {

		if (! KeyType.OKP.equals(jwk.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jwk.getKty());
		if (! Curve.Bls48581G1.equals(jwk.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jwk.getCrv());

		return new bbs.signatures.KeyPair(jwk.getXdecoded(), jwk.getDdecoded());
	}

	public static bbs.signatures.KeyPair JWK_to_Bls48581G2PrivateKey(JWK jwk) {

		if (! KeyType.OKP.equals(jwk.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jwk.getKty());
		if (! Curve.Bls48581G2.equals(jwk.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jwk.getCrv());

		return new bbs.signatures.KeyPair(jwk.getXdecoded(), jwk.getDdecoded());
	}

	public static byte[] JWK_to_Ed25519PrivateKey(JWK jwk) {

		if (! KeyType.OKP.equals(jwk.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jwk.getKty());
		if (! Curve.Ed25519.equals(jwk.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jwk.getCrv());

		byte[] privateKey = new byte[64];
		System.arraycopy(jwk.getDdecoded(), 0, privateKey, 0, 32);
		System.arraycopy(jwk.getXdecoded(), 0, privateKey, 32, 32);

		return privateKey;
	}

	public static byte[] JWK_to_X25519PrivateKey(JWK jwk) {

		if (! KeyType.OKP.equals(jwk.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jwk.getKty());
		if (! Curve.X25519.equals(jwk.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jwk.getCrv());

		byte[] privateKey = new byte[64];
		System.arraycopy(jwk.getDdecoded(), 0, privateKey, 0, 32);
		System.arraycopy(jwk.getXdecoded(), 0, privateKey, 32, 32);

		return privateKey;
	}

	public static ECPrivateKey JWK_to_P_256PrivateKey(JWK jwk) {

		if (! KeyType.EC.equals(jwk.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jwk.getKty());
		if (! Curve.P_256.equals(jwk.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jwk.getCrv());

		byte[] d = jwk.getDdecoded();
		if (d.length != 32) throw new IllegalArgumentException("Invalid 'd' value (not 32 bytes): " + jwk.getD() + ", length=" + jwk.getDdecoded().length);

		ECPrivateKey privateKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp256r1"));
			BigInteger s = new BigInteger(1, d);
			ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);
			privateKey = (ECPrivateKey) KeyFactory.getInstance("ECDH").generatePrivate(ecPrivateKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return privateKey;
	}

	public static ECPrivateKey JWK_to_P_384PrivateKey(JWK jwk) {

		if (! KeyType.EC.equals(jwk.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jwk.getKty());
		if (! Curve.P_384.equals(jwk.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jwk.getCrv());

		byte[] d = jwk.getDdecoded();
		if (d.length != 48) throw new IllegalArgumentException("Invalid 'd' value (not 48 bytes): " + jwk.getD() + ", length=" + jwk.getDdecoded().length);

		ECPrivateKey privateKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp384r1"));
			BigInteger s = new BigInteger(1, d);
			ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);
			privateKey = (ECPrivateKey) KeyFactory.getInstance("ECDH").generatePrivate(ecPrivateKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return privateKey;
	}

	public static ECPrivateKey JWK_to_P_521PrivateKey(JWK jwk) {

		if (! KeyType.EC.equals(jwk.getKty())) throw new IllegalArgumentException("Incorrect key type: " + jwk.getKty());
		if (! Curve.P_521.equals(jwk.getCrv())) throw new IllegalArgumentException("Incorrect curve: " + jwk.getCrv());

		byte[] d = jwk.getDdecoded();
		if (d.length != 66) throw new IllegalArgumentException("Invalid 'd' value (not 66 bytes): " + jwk.getD() + ", length=" + jwk.getDdecoded().length);

		ECPrivateKey privateKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp521r1"));
			BigInteger s = new BigInteger(1, d);
			ECParameterSpec ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(s, ecParameterSpec);
			privateKey = (ECPrivateKey) KeyFactory.getInstance("ECDH").generatePrivate(ecPrivateKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return privateKey;
	}

	/*
	 * Convenience methods
	 */

	public static byte[] JWK_to_anyPrivateKeyBytes(JWK jwk) {

		KeyTypeName keyType = KeyTypeName_for_JWK.keyTypeName_for_JWK(jwk);

		if (keyType == KeyTypeName.RSA)
			return JWK_to_RSAPrivateKeyBytes(jwk);
		else if (keyType == KeyTypeName.secp256k1)
			return JWK_to_secp256k1PrivateKeyBytes(jwk);
		else if (keyType == KeyTypeName.Bls12381G1)
			return JWK_to_Bls12381G1PrivateKeyBytes(jwk);
		else if (keyType == KeyTypeName.Bls12381G2)
			return JWK_to_Bls12381G2PrivateKeyBytes(jwk);
		else if (keyType == KeyTypeName.Bls48581G1)
			return JWK_to_Bls48581G1PrivateKeyBytes(jwk);
		else if (keyType == KeyTypeName.Bls48581G2)
			return JWK_to_Bls48581G2PrivateKeyBytes(jwk);
		else if (keyType == KeyTypeName.Ed25519)
			return JWK_to_Ed25519PrivateKeyBytes(jwk);
		else if (keyType == KeyTypeName.X25519)
			return JWK_to_X25519PrivateKeyBytes(jwk);
		else if (keyType == KeyTypeName.P_256)
			return JWK_to_P_256PrivateKeyBytes(jwk);
		else if (keyType == KeyTypeName.P_384)
			return JWK_to_P_384PrivateKeyBytes(jwk);
		else if (keyType == KeyTypeName.P_521)
			return JWK_to_P_521PrivateKeyBytes(jwk);
		else
			throw new IllegalArgumentException("Unsupported key type: " + keyType);
	}

	public static byte[] JWK_to_RSAPrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.RSAPrivateKey_to_bytes(JWK_to_RSAPrivateKey(jwk));
	}

	public static byte[] JWK_to_secp256k1PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.secp256k1PrivateKey_to_bytes(JWK_to_secp256k1PrivateKey(jwk));
	}

	public static byte[] JWK_to_Bls12381G1PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.Bls12381G1PrivateKey_to_bytes(JWK_to_Bls12381G1PrivateKey(jwk));
	}

	public static byte[] JWK_to_Bls12381G2PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.Bls12381G2PrivateKey_to_bytes(JWK_to_Bls12381G2PrivateKey(jwk));
	}

	public static byte[] JWK_to_Bls48581G1PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.Bls48581G1PrivateKey_to_bytes(JWK_to_Bls48581G1PrivateKey(jwk));
	}

	public static byte[] JWK_to_Bls48581G2PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.Bls48581G2PrivateKey_to_bytes(JWK_to_Bls48581G2PrivateKey(jwk));
	}

	public static byte[] JWK_to_Ed25519PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.Ed25519PrivateKey_to_bytes(JWK_to_Ed25519PrivateKey(jwk));
	}

	public static byte[] JWK_to_X25519PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.X25519PrivateKey_to_bytes(JWK_to_X25519PrivateKey(jwk));
	}

	public static byte[] JWK_to_P_256PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.P_256PrivateKey_to_bytes(JWK_to_P_256PrivateKey(jwk));
	}

	public static byte[] JWK_to_P_384PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.P_384PrivateKey_to_bytes(JWK_to_P_384PrivateKey(jwk));
	}

	public static byte[] JWK_to_P_521PrivateKeyBytes(JWK jwk) {
		return PrivateKeyBytes.P_521PrivateKey_to_bytes(JWK_to_P_521PrivateKey(jwk));
	}
}
