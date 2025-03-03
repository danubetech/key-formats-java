package com.danubetech.keyformats.provider;

import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.crypto.provider.SHA512Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA512Provider;
import com.danubetech.keyformats.crypto.provider.impl.NaClSodiumSHA256Provider;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class SHA512ProviderTest {

	@Test
	public void testJavaSHA512Provider() throws Exception {
		this.internalTest(new JavaSHA512Provider());
	}

	private void internalTest(SHA512Provider sha512Provider) throws Exception {
		byte[] zeros = new byte[512];
		Arrays.fill(zeros, (byte) 0);
		byte[] content = "Hello World".getBytes(StandardCharsets.UTF_8);
		byte[] sha512 = sha512Provider.sha512(content);
		assertEquals(sha512.length, 64);
		assertFalse(Arrays.equals(sha512, zeros));
		assertArrayEquals(sha512, Hex.decodeHex("2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b".toCharArray()));
	}
}
