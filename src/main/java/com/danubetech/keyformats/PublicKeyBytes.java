package com.danubetech.keyformats;

import bbs.signatures.KeyPair;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.crypto.LazyECPoint;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

public class PublicKeyBytes {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/*
	 * RSA
	 */

	public static byte[] RSAPublicKey_to_bytes(RSAPublicKey publicKey) {

		return publicKey.getEncoded();
	}

	public static RSAPublicKey bytes_to_RSAPublicKey(byte[] publicKeyBytes) {

		RSAPublicKey publicKey;
		try {
			publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}
		return publicKey;
	}

	/*
	 * secp256k1
	 */

	public static byte[] secp256k1PublicKey_to_bytes(ECKey publicKey) {

		byte[] publicKeyBytes = ECKey.fromPublicOnly(new LazyECPoint(publicKey.getPubKeyPoint(), true).get(), true).getPubKey();
		if (publicKeyBytes.length != 33) throw new IllegalArgumentException("Invalid key size (not 33 bytes): " + Hex.encodeHexString(publicKeyBytes) + ", length=" + publicKeyBytes.length);

		return publicKeyBytes;
	}

	public static ECKey bytes_to_secp256k1PublicKey(byte[] publicKeyBytes) {

		if (publicKeyBytes.length != 33) throw new IllegalArgumentException("Invalid key size (not 33 bytes): " + Hex.encodeHexString(publicKeyBytes) + ", length=" + publicKeyBytes.length);

		return ECKey.fromPublicOnly(publicKeyBytes);
	}

	/*
	 * Bls12381G1
	 */

	public static byte[] Bls12381G1PublicKey_to_bytes(KeyPair publicKey) {

		return publicKey.publicKey;
	}

	public static KeyPair bytes_to_Bls12381G1PublicKey(byte[] publicKeyBytes) {

		return new KeyPair(publicKeyBytes, null);
	}

	/*
	 * Bls12381G2
	 */

	public static byte[] Bls12381G2PublicKey_to_bytes(KeyPair publicKey) {

		return publicKey.publicKey;
	}

	public static KeyPair bytes_to_Bls12381G2PublicKey(byte[] publicKeyBytes) {

		return new KeyPair(publicKeyBytes, null);
	}

	/*
	 * Bls48581G1
	 */

	public static byte[] Bls48581G1PublicKey_to_bytes(KeyPair publicKey) {

		return publicKey.publicKey;
	}

	public static KeyPair bytes_to_Bls48581G1PublicKey(byte[] publicKeyBytes) {

		return new KeyPair(publicKeyBytes, null);
	}

	/*
	 * Bls48581G2
	 */

	public static byte[] Bls48581G2PublicKey_to_bytes(KeyPair publicKey) {

		return publicKey.publicKey;
	}

	public static KeyPair bytes_to_Bls48581G2PublicKey(byte[] publicKeyBytes) {

		return new KeyPair(publicKeyBytes, null);
	}

	/*
	 * Ed25519
	 */

	public static byte[] Ed25519PublicKey_to_bytes(byte[] publicKey) {

		if (publicKey.length != 32) throw new IllegalArgumentException("Expected 32 bytes instead of " + publicKey.length);

		return publicKey;
	}

	public static byte[] bytes_to_Ed25519PublicKey(byte[] publicKeyBytes) {

		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Expected 32 bytes instead of " + publicKeyBytes.length);

		return publicKeyBytes;
	}

	/*
	 * X25519
	 */

	public static byte[] X25519PublicKey_to_bytes(byte[] publicKey) {

		if (publicKey.length != 32) throw new IllegalArgumentException("Expected 32 bytes instead of " + publicKey.length);

		return publicKey;
	}

	public static byte[] bytes_to_X25519PublicKey(byte[] publicKeyBytes) {

		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Expected 32 bytes instead of " + publicKeyBytes.length);

		return publicKeyBytes;
	}

	/*
	 * P-256
	 */

	public static byte[] P_256PublicKey_to_bytes(ECPublicKey publicKey) {

		byte[] point = EC5Util.convertPoint(publicKey.getParams(), publicKey.getW()).getEncoded(true);
		if (point.length != 33) throw new IllegalArgumentException("Invalid key size (not 33 bytes): " + Hex.encodeHexString(point) + ", length=" + point.length);
		return point;
	}

	public static ECPublicKey bytes_to_P_256PublicKey(byte[] publicKeyBytes) {

		if (publicKeyBytes.length != 33) throw new IllegalArgumentException("Expected 33 bytes instead of " + publicKeyBytes.length);

		ECNamedCurveParameterSpec ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
		org.bouncycastle.math.ec.ECPoint bcEcPoint = ecNamedCurveParameterSpec.getCurve().decodePoint(publicKeyBytes);
		byte[] x = bcEcPoint.getRawXCoord().getEncoded();
		byte[] y = bcEcPoint.getRawYCoord().getEncoded();

		ECPublicKey publicKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp256r1"));
			ECPoint ecPoint = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
			ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, parameters.getParameterSpec(ECParameterSpec.class));
			publicKey = (ECPublicKey) KeyFactory.getInstance("ECDH").generatePublic(ecPublicKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return publicKey;
	}

	/*
	 * P-384
	 */

	public static byte[] P_384PublicKey_to_bytes(ECPublicKey publicKey) {

		byte[] point = EC5Util.convertPoint(publicKey.getParams(), publicKey.getW()).getEncoded(true);
		if (point.length != 49) throw new IllegalArgumentException("Invalid key size (not 49 bytes): " + Hex.encodeHexString(point) + ", length=" + point.length);
		return point;
	}

	public static ECPublicKey bytes_to_P_384PublicKey(byte[] publicKeyBytes) {

		if (publicKeyBytes.length != 49) throw new IllegalArgumentException("Expected 49 bytes instead of " + publicKeyBytes.length);

		ECNamedCurveParameterSpec ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
		org.bouncycastle.math.ec.ECPoint bcEcPoint = ecNamedCurveParameterSpec.getCurve().decodePoint(publicKeyBytes);
		byte[] x = bcEcPoint.getRawXCoord().getEncoded();
		byte[] y = bcEcPoint.getRawYCoord().getEncoded();

		ECPublicKey publicKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp384r1"));
			ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
			ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, parameters.getParameterSpec(ECParameterSpec.class));
			publicKey = (ECPublicKey) KeyFactory.getInstance("ECDH").generatePublic(ecPublicKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return publicKey;
	}

	/*
	 * P-521
	 */

	public static byte[] P_521PublicKey_to_bytes(ECPublicKey publicKey) {

		byte[] point = EC5Util.convertPoint(publicKey.getParams(), publicKey.getW()).getEncoded(true);
		if (point.length != 65 && point.length != 66 && point.length != 67) throw new IllegalArgumentException("Invalid key size (not 65 or 66 or 67 bytes): " + Hex.encodeHexString(point) + ", length=" + point.length);
		return point;
	}

	public static ECPublicKey bytes_to_P_521PublicKey(byte[] publicKeyBytes) {

		if (publicKeyBytes.length != 65 && publicKeyBytes.length != 66 && publicKeyBytes.length != 67) throw new IllegalArgumentException("Expected 65 or 66 or 67 bytes instead of " + publicKeyBytes.length);

		ECNamedCurveParameterSpec ecNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
		org.bouncycastle.math.ec.ECPoint bcEcPoint = ecNamedCurveParameterSpec.getCurve().decodePoint(publicKeyBytes);
		byte[] x = bcEcPoint.getRawXCoord().getEncoded();
		byte[] y = bcEcPoint.getRawYCoord().getEncoded();

		ECPublicKey publicKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp521r1"));
			ECPoint w = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
			ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(w, parameters.getParameterSpec(ECParameterSpec.class));
			publicKey = (ECPublicKey) KeyFactory.getInstance("ECDH").generatePublic(ecPublicKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return publicKey;
	}
}
