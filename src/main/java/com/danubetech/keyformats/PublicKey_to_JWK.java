package com.danubetech.keyformats;

import bbs.signatures.KeyPair;
import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import com.danubetech.keyformats.util.ByteArrayUtil;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.crypto.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.util.Base64;

public class PublicKey_to_JWK {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static JWK RSAPublicKey_to_JWK(RSAPublicKey publicKey, String kid, String use) {

		JWK jwk = new JWK();
		jwk.setKty(KeyType.RSA);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setN(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArrayUtil.bigIntegertoByteArray(publicKey.getModulus())));
		jwk.setE(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArrayUtil.bigIntegertoByteArray(publicKey.getPublicExponent())));

		return jwk;
	}

	public static JWK secp256k1PublicKey_to_JWK(ECKey publicKey, String kid, String use) {

		org.bouncycastle.math.ec.ECPoint publicKeyPoint = publicKey.getPubKeyPoint();

		if (publicKeyPoint.getAffineXCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + new String(Hex.encodeHex(publicKeyPoint.getAffineXCoord().getEncoded())) + ", length=" + publicKeyPoint.getAffineXCoord().getEncoded().length);
		if (publicKeyPoint.getAffineYCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + new String(Hex.encodeHex(publicKeyPoint.getAffineYCoord().getEncoded())) + ", length=" + publicKeyPoint.getAffineYCoord().getEncoded().length);

		JWK jwk = new JWK();
		jwk.setKty(KeyType.EC);
		jwk.setCrv(Curve.secp256k1);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyPoint.getAffineXCoord().getEncoded()));
		jwk.setY(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyPoint.getAffineYCoord().getEncoded()));

		return jwk;
	}

	public static JWK Bls12381G1PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;
		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): " + Hex.encodeHexString(publicKeyBytes));

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.Bls12381G1);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jwk;
	}

	public static JWK Bls12381G2PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;
		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): " + Hex.encodeHexString(publicKeyBytes));

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.Bls12381G2);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jwk;
	}

	public static JWK Bls48581G1PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;
		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): " + Hex.encodeHexString(publicKeyBytes));

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.Bls48581G1);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jwk;
	}

	public static JWK Bls48581G2PublicKey_to_JWK(KeyPair publicKey, String kid, String use) {

		byte[] publicKeyBytes = publicKey.publicKey;
		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): " + Hex.encodeHexString(publicKeyBytes));

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.Bls48581G2);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jwk;
	}

	public static JWK Ed25519PublicKey_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): " + Hex.encodeHexString(publicKeyBytes));

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.Ed25519);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jwk;
	}

	public static JWK X25519PublicKey_to_JWK(byte[] publicKeyBytes, String kid, String use) {

		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): " + Hex.encodeHexString(publicKeyBytes));

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.X25519);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));

		return jwk;
	}

	public static JWK P_256PublicKey_to_JWK(ECPublicKey publicKey, String kid, String use) {

		ECPoint publicKeyPoint = publicKey.getW();

		byte[] x = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineX());
		if (x.length < 30 || x.length > 32) throw new IllegalArgumentException("Invalid 'x' value (<30 or >32 bytes): " + new String(Hex.encodeHex(x)) + ", length=" + x.length + " (" + publicKeyPoint.getAffineX().bitLength() + " bits)");
		x = ByteArrayUtil.padArrayZeros(x, 32);
		byte[] y = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineY());
		if (y.length < 30 || y.length > 32) throw new IllegalArgumentException("Invalid 'y' value (<30 or >32 bytes): " + new String(Hex.encodeHex(y)) + ", length=" + y.length + " (" + publicKeyPoint.getAffineY().bitLength() + " bits)");
		y = ByteArrayUtil.padArrayZeros(y, 32);

		JWK jwk = new JWK();
		jwk.setKty(KeyType.EC);
		jwk.setCrv(Curve.P_256);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(x));
		jwk.setY(Base64.getUrlEncoder().withoutPadding().encodeToString(y));

		return jwk;
	}

	public static JWK P_384PublicKey_to_JWK(ECPublicKey publicKey, String kid, String use) {

		ECPoint publicKeyPoint = publicKey.getW();

		byte[] x = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineX());
		if (x.length < 46 || x.length > 48) throw new IllegalArgumentException("Invalid 'x' value (<46 or >48 bytes): " + new String(Hex.encodeHex(x)) + ", length=" + x.length + " (" + publicKeyPoint.getAffineX().bitLength() + " bits)");
		x = ByteArrayUtil.padArrayZeros(x, 48);
		byte[] y = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineY());
		if (y.length < 46 || y.length > 48) throw new IllegalArgumentException("Invalid 'y' value (<46 or >48 bytes): " + new String(Hex.encodeHex(y)) + ", length=" + y.length + " (" + publicKeyPoint.getAffineY().bitLength() + " bits)");
		y = ByteArrayUtil.padArrayZeros(y, 48);

		JWK jwk = new JWK();
		jwk.setKty(KeyType.EC);
		jwk.setCrv(Curve.P_384);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(x));
		jwk.setY(Base64.getUrlEncoder().withoutPadding().encodeToString(y));

		return jwk;
	}

	public static JWK P_521PublicKey_to_JWK(ECPublicKey publicKey, String kid, String use) {

		ECPoint publicKeyPoint = publicKey.getW();

		byte[] x = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineX());
		if (x.length < 64 || x.length > 66) throw new IllegalArgumentException("Invalid 'x' value (<64 or >66 bytes): " + new String(Hex.encodeHex(x)) + ", length=" + x.length + " (" + publicKeyPoint.getAffineX().bitLength() + " bits)");
		x = ByteArrayUtil.padArrayZeros(x, 66);
		byte[] y = ByteArrayUtil.bigIntegertoByteArray(publicKeyPoint.getAffineY());
		if (y.length < 64 || y.length > 66) throw new IllegalArgumentException("Invalid 'y' value (<64 or >66 bytes): " + new String(Hex.encodeHex(y)) + ", length=" + y.length + " (" + publicKeyPoint.getAffineY().bitLength() + " bits)");
		y = ByteArrayUtil.padArrayZeros(y, 66);

		JWK jwk = new JWK();
		jwk.setKty(KeyType.EC);
		jwk.setCrv(Curve.P_521);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(x));
		jwk.setY(Base64.getUrlEncoder().withoutPadding().encodeToString(y));

		return jwk;
	}

	/*
	 * Convenience methods
	 */

	public static JWK RSAPublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return RSAPublicKey_to_JWK(PublicKeyBytes.bytes_to_RSAPublicKey(publicKeyBytes), kid, use);
	}

	public static JWK secp256k1PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return secp256k1PublicKey_to_JWK(PublicKeyBytes.bytes_to_secp256k1PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK Bls12381G1PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return Bls12381G1PublicKey_to_JWK(PublicKeyBytes.bytes_to_Bls12381G1PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK Bls12381G2PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return Bls12381G2PublicKey_to_JWK(PublicKeyBytes.bytes_to_Bls12381G2PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK Bls48581G1PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return Bls48581G1PublicKey_to_JWK(PublicKeyBytes.bytes_to_Bls48581G1PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK Bls48581G2PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return Bls48581G2PublicKey_to_JWK(PublicKeyBytes.bytes_to_Bls48581G2PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK Ed25519PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return Ed25519PublicKey_to_JWK(PublicKeyBytes.bytes_to_Ed25519PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK X25519PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return X25519PublicKey_to_JWK(PublicKeyBytes.bytes_to_X25519PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK P_256PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return P_256PublicKey_to_JWK(PublicKeyBytes.bytes_to_P_256PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK P_384PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return P_384PublicKey_to_JWK(PublicKeyBytes.bytes_to_P_384PublicKey(publicKeyBytes), kid, use);
	}

	public static JWK P_521PublicKeyBytes_to_JWK(byte[] publicKeyBytes, String kid, String use) {
		return P_521PublicKey_to_JWK(PublicKeyBytes.bytes_to_P_521PublicKey(publicKeyBytes), kid, use);
	}
}
