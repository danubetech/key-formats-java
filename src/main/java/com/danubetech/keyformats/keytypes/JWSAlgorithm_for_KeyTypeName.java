package com.danubetech.keyformats.keytypes;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.util.List;
import java.util.Map;

public class JWSAlgorithm_for_KeyTypeName {

	private static final Map<KeyTypeName, List<String>> JWS_ALGORITHMS_BY_KEY_TYPE_NAME = Map.ofEntries(
			Map.entry(KeyTypeName.RSA, List.of(JWSAlgorithm.RS256, JWSAlgorithm.PS256)),
			Map.entry(KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K, JWSAlgorithm.ES256KCC, JWSAlgorithm.ES256KRR, JWSAlgorithm.ES256KS, JWSAlgorithm.MUSIG2)),
			Map.entry(KeyTypeName.Bls12381G1, List.of(JWSAlgorithm.BBSPlus)),
			Map.entry(KeyTypeName.Bls12381G2, List.of(JWSAlgorithm.BBSPlus)),
			Map.entry(KeyTypeName.Bls48581G1, List.of(JWSAlgorithm.BBSPlus)),
			Map.entry(KeyTypeName.Bls48581G2, List.of(JWSAlgorithm.BBSPlus)),
			Map.entry(KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA)),
			Map.entry(KeyTypeName.P_256, List.of(JWSAlgorithm.ES256)),
			Map.entry(KeyTypeName.P_384, List.of(JWSAlgorithm.ES384)),
			Map.entry(KeyTypeName.P_521, List.of(JWSAlgorithm.ES512)),
			Map.entry(KeyTypeName.ML_DSA_44, List.of(JWSAlgorithm.ML_DSA_44)),
			Map.entry(KeyTypeName.ML_DSA_65, List.of(JWSAlgorithm.ML_DSA_65)),
			Map.entry(KeyTypeName.ML_DSA_87, List.of(JWSAlgorithm.ML_DSA_87))
	);

	public static List<String> jwsAlgorithms_for_KeyTypeName(KeyTypeName keyTypeName) {

		return JWS_ALGORITHMS_BY_KEY_TYPE_NAME.get(keyTypeName);
	}

	public static String defaultJwsAlgorithm_for_KeyTypeName(KeyTypeName keyTypeName) {

		List<String> jwsAlgorithms = jwsAlgorithms_for_KeyTypeName(keyTypeName);
		return (jwsAlgorithms == null || jwsAlgorithms.isEmpty()) ? null : jwsAlgorithms.get(0);
	}
}
