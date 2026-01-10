package com.danubetech.keyformats;

import com.danubetech.keyformats.jose.Curve;
import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.KeyType;
import com.danubetech.keyformats.util.ByteArrayUtil;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.crypto.ECKey;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;

public class PrivateKey_to_JWK {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static JWK RSAPrivateKey_to_JWK(KeyPair privateKey, String kid, String use) {

		JWK jwk = new JWK();
		jwk.setKty(KeyType.RSA);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setN(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArrayUtil.bigIntegertoByteArray(((RSAPublicKey) privateKey.getPublic()).getModulus())));
		jwk.setE(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArrayUtil.bigIntegertoByteArray(((RSAPublicKey) privateKey.getPublic()).getPublicExponent())));
		jwk.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArrayUtil.bigIntegertoByteArray(((RSAPrivateKey) privateKey.getPrivate()).getPrivateExponent())));

		return jwk;
	}

	public static JWK secp256k1PrivateKey_to_JWK(ECKey privateKey, String kid, String use) {

		org.bouncycastle.math.ec.ECPoint publicKeyPoint = privateKey.getPubKeyPoint();
		byte[] privateKeyBytes = privateKey.getPrivKeyBytes();

		if (publicKeyPoint.getAffineXCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'x' value (not 32 bytes): " + Hex.encodeHexString(publicKeyPoint.getAffineXCoord().getEncoded()) + ", length=" + publicKeyPoint.getAffineXCoord().getEncoded().length);
		if (publicKeyPoint.getAffineYCoord().getEncoded().length != 32) throw new IllegalArgumentException("Invalid 'y' value (not 32 bytes): " + Hex.encodeHexString(publicKeyPoint.getAffineYCoord().getEncoded()) + ", length=" + publicKeyPoint.getAffineYCoord().getEncoded().length);
		if (privateKeyBytes.length != 32) throw new IllegalArgumentException("Invalid 'd' value (not 32 bytes): length=" + privateKeyBytes.length);

		JWK jwk = new JWK();
		jwk.setKty(KeyType.EC);
		jwk.setCrv(Curve.secp256k1);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyPoint.getAffineXCoord().getEncoded()));
		jwk.setY(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyPoint.getAffineYCoord().getEncoded()));
		jwk.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes));

		return jwk;
	}

	public static JWK Bls12381G1PrivateKey_to_JWK(bbs.signatures.KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;
		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): " + Hex.encodeHexString(publicKeyBytes));
		if (privateKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): private key");

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.Bls12381G1);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
		jwk.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes));

		return jwk;
	}

	public static JWK Bls12381G2PrivateKey_to_JWK(bbs.signatures.KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;
		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): " + Hex.encodeHexString(publicKeyBytes));
		if (privateKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): private key");

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.Bls12381G2);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
		jwk.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes));

		return jwk;
	}

	public static JWK Bls48581G1PrivateKey_to_JWK(bbs.signatures.KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;
		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): " + Hex.encodeHexString(publicKeyBytes));
		if (privateKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): private key");

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.Bls48581G1);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
		jwk.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes));

		return jwk;
	}

	public static JWK Bls48581G2PrivateKey_to_JWK(bbs.signatures.KeyPair privateKey, String kid, String use) {

		byte[] publicKeyBytes = privateKey.publicKey;
		byte[] privateKeyBytes = privateKey.secretKey;
		if (publicKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): " + Hex.encodeHexString(publicKeyBytes));
		if (privateKeyBytes.length != 32) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): private key");

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.Bls48581G2);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes));
		jwk.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(privateKeyBytes));

		return jwk;
	}

	public static JWK Ed25519PrivateKey_to_JWK(byte[] privateKey, String kid, String use) {

		if (privateKey.length != 64) throw new IllegalArgumentException("Invalid byte value (not 64 bytes): private key");

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.Ed25519);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(privateKey, 32, 64)));
		jwk.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(privateKey, 0, 32)));

		return jwk;
	}

	public static JWK X25519PrivateKey_to_JWK(byte[] privateKey, String kid, String use) {

		if (privateKey.length != 64) throw new IllegalArgumentException("Invalid byte value (not 32 bytes): private key");

		JWK jwk = new JWK();
		jwk.setKty(KeyType.OKP);
		jwk.setCrv(Curve.X25519);
		jwk.setKid(kid);
		jwk.setUse(use);
		jwk.setX(Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(privateKey, 32, 64)));
		jwk.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOfRange(privateKey, 0, 32)));

		return jwk;
	}

	public static JWK P_256PrivateKey_to_JWK(ECPrivateKey privateKey, String kid, String use) {

		byte[] d = ByteArrayUtil.bigIntegertoByteArray(privateKey.getS());
		if (d.length < 30 || d.length > 32) throw new IllegalArgumentException("Invalid 'd' value (<30 or >32 bytes): private key, length=" + d.length + " (" + privateKey.getS().bitLength() + " bits)");
		d = ByteArrayUtil.padArrayZeros(d, 32);

		ECPoint publicKeyPoint;
		try {
			org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
			org.bouncycastle.math.ec.ECPoint ecPoint = ecParameterSpec.getG().multiply(privateKey.getS());
			org.bouncycastle.math.ec.ECPoint ecPointDecoded = ecParameterSpec.getCurve().decodePoint(ecPoint.getEncoded(false));
			publicKeyPoint = new ECPoint(ecPointDecoded.getXCoord().toBigInteger(), ecPointDecoded.getYCoord().toBigInteger());
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

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
		jwk.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(d));

		return jwk;
	}

	public static JWK P_384PrivateKey_to_JWK(ECPrivateKey privateKey, String kid, String use) {

		byte[] d = ByteArrayUtil.bigIntegertoByteArray(privateKey.getS());
		if (d.length < 46 || d.length > 48) throw new IllegalArgumentException("Invalid 'd' value (<46 or >48 bytes): private key, length=" + d.length + " (" + privateKey.getS().bitLength() + " bits)");
		d = ByteArrayUtil.padArrayZeros(d, 48);

		ECPoint publicKeyPoint;
		try {
			org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp384r1");
			org.bouncycastle.math.ec.ECPoint ecPoint = ecParameterSpec.getG().multiply(privateKey.getS());
			org.bouncycastle.math.ec.ECPoint ecPointDecoded = ecParameterSpec.getCurve().decodePoint(ecPoint.getEncoded(false));
			publicKeyPoint = new ECPoint(ecPointDecoded.getXCoord().toBigInteger(), ecPointDecoded.getYCoord().toBigInteger());
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

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
		jwk.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(d));

		return jwk;
	}

	public static JWK P_521PrivateKey_to_JWK(ECPrivateKey privateKey, String kid, String use) {

		byte[] d = ByteArrayUtil.bigIntegertoByteArray(privateKey.getS());
		if (d.length < 64 || d.length > 66) throw new IllegalArgumentException("Invalid 'd' value (<64 or >66 bytes): private key, length=" + d.length + " (" + privateKey.getS().bitLength() + " bits)");
		d = ByteArrayUtil.padArrayZeros(d, 66);

		ECPoint publicKeyPoint;
		try {
			org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp521r1");
			org.bouncycastle.math.ec.ECPoint ecPoint = ecParameterSpec.getG().multiply(privateKey.getS());
			org.bouncycastle.math.ec.ECPoint ecPointDecoded = ecParameterSpec.getCurve().decodePoint(ecPoint.getEncoded(false));
			publicKeyPoint = new ECPoint(ecPointDecoded.getXCoord().toBigInteger(), ecPointDecoded.getYCoord().toBigInteger());
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

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
		jwk.setD(Base64.getUrlEncoder().withoutPadding().encodeToString(d));

		return jwk;
	}

	/*
	 * Convenience methods
	 */

	public static JWK RSAPrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return RSAPrivateKey_to_JWK(PrivateKeyBytes.bytes_to_RSAPrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK secp256k1PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return secp256k1PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_secp256k1PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK Bls12381G1PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return Bls12381G1PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_Bls12381G1PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK Bls12381G2PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return Bls12381G2PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_Bls12381G2PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK Bls48581G1PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return Bls48581G1PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_Bls48581G1PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK Bls48581G2PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return Bls48581G2PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_Bls48581G2PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK Ed25519PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return Ed25519PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_Ed25519PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK X25519PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return X25519PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_X25519PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK P_256PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return P_256PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_P_256PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK P_384PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return P_384PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_P_384PrivateKey(privateKeyBytes), kid, use);
	}

	public static JWK P_521PrivateKeyBytes_to_JWK(byte[] privateKeyBytes, String kid, String use) {
		return P_521PrivateKey_to_JWK(PrivateKeyBytes.bytes_to_P_521PrivateKey(privateKeyBytes), kid, use);
	}
}
