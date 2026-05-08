package com.danubetech.keyformats.crypto;

import com.danubetech.keyformats.jose.JWK;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SignMUSIG2Test {

	public static final JWK jwkPublic;
	public static final JWK jwkPrivate;

	static {
		try {
			jwkPublic = JWK.fromJson("""
                    {
                      "kty" : "EC",
                      "crv" : "secp256k1",
                      "x" : "HOSoup-TMF1JgpDOVUAlxoF6a_gB3-lBANl9gz9cXSY",
                      "y" : "p-DMQ4bB7LpVaWhskYcFayr6i3Icp-eTZw7IhLYPtYA"
                    }""");
			jwkPrivate = JWK.fromJson("""
                    {
                      "kty" : "EC",
                      "crv" : "secp256k1",
                      "x" : "HOSoup-TMF1JgpDOVUAlxoF6a_gB3-lBANl9gz9cXSY",
                      "y" : "p-DMQ4bB7LpVaWhskYcFayr6i3Icp-eTZw7IhLYPtYA",
                      "d" : "eqadTOcFR-dWd-R7AsuF3efe5zqdIzrwizrG1UnE470"
                    }""");
		} catch (IOException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	private static final byte[] CONTENT = """
			{
			  "tx": "AQAAAAGfh0lHJgqi8niVwNIrzbu4+Oaf69vUEYuO/pvhk4a2WgAAAAAiUSBwsdFgu4SAxQd4YcxfIxBp6/FxSvd1By6eh+FsRxglm/////8ChAMAAAAAAAAiUSBwsdFgu4SAxQd4YcxfIxBp6/FxSvd1By6eh+FsRxglmwAAAAAAAAAAImogpvHeIa3T5VaR2RGHtAsyL+aF386nvzT3995F6EjdhukAAAAA",
			  "inputIndex": 0,
			  "inputs": [
			    "6AMAAAAAAAAiUSBwsdFgu4SAxQd4YcxfIxBp6/FxSvd1By6eh+FsRxglmw=="
			  ],
			  "publicKeys": [
			    "AhzkqLqfkzBdSYKQzlVAJcaBemv4Ad/pQQDZfYM/XF0m",
			    "Ap96IBePVhAjyTMksQ/5P+nRNVmoR4Jd2tQ8PqqVw12s"
			  ],
			  "secretNonce": "Ig7c8XzXYN0nhVQ11m+ImGVBZzHGRYRhqDyuEGw87qYe+YMVVVZbfBDU/vJEcPebJX/hT+xz4AcGEOy0bgorM1aKdM0mXVw/g33ZAEHp3wH4a3qBxiVAVc6QgkldMJOfuqjkHIC1D7aEyA5nk+enHHKL+iprBYeRbGhpVbrswYZDzOCn",
			  "publicNonces": [
			    "AkG//BABVlYbPI+c7lPiJhDhgZjROQaTviHRIiOfEJjSAhe8GYHoc8ZwEWa+6QdTlY19UUE/+NfcN8VfQsAq6O2G",
			    "AoAz0rDRwx1cvw7+SdlMSqSlLRy0IcF+X46DQ22kQ+eAAupRmUTT4vg2wzPZNqSs7AeB5L/e3LoOQaQkudILO5Hg"
			  ]
			}
			""".getBytes(StandardCharsets.UTF_8);

	private static final PrivateKeySigner<?> privateKeySigner = PrivateKeySignerFactory.privateKeySignerForKey(jwkPrivate, JWSAlgorithm.MUSIG2);

	@Test
	public void testSignVerify() throws Exception {

		byte[] signature = privateKeySigner.sign(CONTENT);
		assertNotNull(signature);
	}
}
