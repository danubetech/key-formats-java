package com.danubetech.keyformats;

import com.danubetech.keyformats.util.ByteArrayUtil;
import org.bitcoinj.crypto.ECKey;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.util.Arrays;

public class PrivateKeyBytes {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	/*
	 * RSA
	 */

	public static byte[] RSAPrivateKey_to_bytes(KeyPair privateKey) {

		try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			 ObjectOutputStream objectOutputStream =  new ObjectOutputStream(byteArrayOutputStream)) {
			objectOutputStream.writeObject(privateKey);
			return byteArrayOutputStream.toByteArray();
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}
	}

	public static KeyPair bytes_to_RSAPrivateKey(byte[] privateKeyBytes) {

		try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(privateKeyBytes);
			 ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream)) {
			return (KeyPair) objectInputStream.readObject();
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}
	}

	/*
	 * secp256k1
	 */

	public static byte[] secp256k1PrivateKey_to_bytes(ECKey privateKey) {

		return privateKey.getPrivKeyBytes();
	}

	public static ECKey bytes_to_secp256k1PrivateKey(byte[] privateKeyBytes) {

		return ECKey.fromPrivate(privateKeyBytes);
	}

	/*
	 * Bls12381G1
	 */

	public static byte[] Bls12381G1PrivateKey_to_bytes(bbs.signatures.KeyPair privateKey) {

		return privateKey.secretKey;
	}

	public static bbs.signatures.KeyPair bytes_to_Bls12381G1PrivateKey(byte[] privateKeyBytes) {

		return new bbs.signatures.KeyPair(null, privateKeyBytes);
	}

	/*
	 * Bls12381G2
	 */

	public static byte[] Bls12381G2PrivateKey_to_bytes(bbs.signatures.KeyPair privateKey) {

		return privateKey.secretKey;
	}

	public static bbs.signatures.KeyPair bytes_to_Bls12381G2PrivateKey(byte[] privateKeyBytes) {

		return new bbs.signatures.KeyPair(null, privateKeyBytes);
	}

	/*
	 * Bls48581G1
	 */

	public static byte[] Bls48581G1PrivateKey_to_bytes(bbs.signatures.KeyPair privateKey) {

		return privateKey.secretKey;
	}

	public static bbs.signatures.KeyPair bytes_to_Bls48581G1PrivateKey(byte[] privateKeyBytes) {

		return new bbs.signatures.KeyPair(null, privateKeyBytes);
	}

	/*
	 * Bls48581G2
	 */

	public static byte[] Bls48581G2PrivateKey_to_bytes(bbs.signatures.KeyPair privateKey) {

		return privateKey.secretKey;
	}

	public static bbs.signatures.KeyPair bytes_to_Bls48581G2PrivateKey(byte[] privateKeyBytes) {

		return new bbs.signatures.KeyPair(null, privateKeyBytes);
	}

	/*
	 * Ed25519
	 */

	public static byte[] Ed25519PrivateKey_to_bytes(byte[] privateKey) {

		if (privateKey.length != 64) throw new IllegalArgumentException("Expected 32 bytes instead of " + privateKey.length);

		return Arrays.copyOfRange(privateKey, 0, 32);
	}

	public static byte[] bytes_to_Ed25519PrivateKey(byte[] privateKeyBytes) {

		if (privateKeyBytes.length != 32) throw new IllegalArgumentException("Expected 32 bytes instead of " + privateKeyBytes.length);

		Ed25519PrivateKeyParameters ed25519PublicKeyParameters = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
		Ed25519PublicKeyParameters ed25519PublicKeyParameters1 = ed25519PublicKeyParameters.generatePublicKey();

		byte[] privateKey = new byte[64];
		System.arraycopy(privateKeyBytes, 0, privateKey, 0, 32);
		System.arraycopy(ed25519PublicKeyParameters1.getEncoded(), 0, privateKey, 32, 32);

		return privateKey;
	}

	/*
	 * X25519
	 */

	public static byte[] X25519PrivateKey_to_bytes(byte[] privateKey) {

		if (privateKey.length != 64) throw new IllegalArgumentException("Expected 32 bytes instead of " + privateKey.length);

		return Arrays.copyOfRange(privateKey, 0, 32);
	}

	public static byte[] bytes_to_X25519PrivateKey(byte[] privateKeyBytes) {

		if (privateKeyBytes.length != 32) throw new IllegalArgumentException("Expected 32 bytes instead of " + privateKeyBytes.length);

		X25519PrivateKeyParameters x25519PrivateKeyParameters = new X25519PrivateKeyParameters(privateKeyBytes, 0);
		X25519PublicKeyParameters x25519PublicKeyParameters = x25519PrivateKeyParameters.generatePublicKey();

		byte[] privateKey = new byte[64];
		System.arraycopy(privateKeyBytes, 0, privateKey, 0, 32);
		System.arraycopy(x25519PublicKeyParameters.getEncoded(), 0, privateKey, 32, 32);

		return privateKey;
	}

	/*
	 * P-256
	 */

	public static byte[] P_256PrivateKey_to_bytes(ECPrivateKey privateKey) {

		byte[] s = ByteArrayUtil.bigIntegertoByteArray(privateKey.getS());
		if (s.length != 32) throw new IllegalArgumentException("Invalid key size (not 32 bytes): private key, length=" + s.length + " (" + privateKey.getS().bitLength() + " bits)");

		return s;
	}

	public static ECPrivateKey bytes_to_P_256PrivateKey(byte[] privateKeyBytes) {

		if (privateKeyBytes.length != 32) throw new IllegalArgumentException("Expected 32 bytes instead of " + privateKeyBytes.length);

		ECPrivateKey privateKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp256r1"));
			BigInteger s = new BigInteger(1, privateKeyBytes);
			ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(s, parameters.getParameterSpec(ECParameterSpec.class));
			privateKey = (ECPrivateKey) KeyFactory.getInstance("ECDH").generatePrivate(ecPrivateKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return privateKey;
	}

	/*
	 * P-384
	 */

	public static byte[] P_384PrivateKey_to_bytes(ECPrivateKey privateKey) {

		byte[] s = ByteArrayUtil.bigIntegertoByteArray(privateKey.getS());
		if (s.length != 48) throw new IllegalArgumentException("Invalid key size (not 48 bytes): private key, length=" + s.length + " (" + privateKey.getS().bitLength() + " bits)");

		return s;
	}

	public static ECPrivateKey bytes_to_P_384PrivateKey(byte[] privateKeyBytes) {

		if (privateKeyBytes.length != 48) throw new IllegalArgumentException("Expected 48 bytes instead of " + privateKeyBytes.length);

		ECPrivateKey privateKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp384r1"));
			BigInteger s = new BigInteger(1, privateKeyBytes);
			ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(s, parameters.getParameterSpec(ECParameterSpec.class));
			privateKey = (ECPrivateKey) KeyFactory.getInstance("ECDH").generatePrivate(ecPrivateKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return privateKey;
	}

	/*
	 * P-521
	 */

	public static byte[] P_521PrivateKey_to_bytes(ECPrivateKey privateKey) {

		byte[] s = ByteArrayUtil.bigIntegertoByteArray(privateKey.getS());
		if (s.length != 64 && s.length != 65 && s.length != 66) throw new IllegalArgumentException("Invalid key size (not 64 or 65 or 66 bytes): private key, length=" + s.length + " (" + privateKey.getS().bitLength() + " bits)");

		return s;
	}

	public static ECPrivateKey bytes_to_P_521PrivateKey(byte[] privateKeyBytes) {

		if (privateKeyBytes.length != 64 && privateKeyBytes.length != 65 && privateKeyBytes.length != 66) throw new IllegalArgumentException("Expected 64 or 65 or 66 bytes instead of " + privateKeyBytes.length);

		ECPrivateKey privateKey;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp521r1"));
			BigInteger s = new BigInteger(1, privateKeyBytes);
			ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(s, parameters.getParameterSpec(ECParameterSpec.class));
			privateKey = (ECPrivateKey) KeyFactory.getInstance("ECDH").generatePrivate(ecPrivateKeySpec);
		} catch (Exception ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}

		return privateKey;
	}
}
