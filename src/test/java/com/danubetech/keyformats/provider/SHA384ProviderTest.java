package com.danubetech.keyformats.provider;

import com.danubetech.keyformats.crypto.provider.SHA384Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA384Provider;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class SHA384ProviderTest {

	@Test
	public void testJavaSHA384Provider() throws Exception {
		this.internalTest(new JavaSHA384Provider());
	}

	private void internalTest(SHA384Provider sha384Provider) throws Exception {
		byte[] zeros = new byte[384];
		Arrays.fill(zeros, (byte) 0);
		byte[] content = "Hello World".getBytes(StandardCharsets.UTF_8);
		byte[] sha384 = sha384Provider.sha384(content);
		assertEquals(sha384.length, 48);
		assertFalse(Arrays.equals(sha384, zeros));
		assertArrayEquals(sha384, Hex.decodeHex("99514329186b2f6ae4a1329e7ee6c610a729636335174ac6b740f9028396fcc803d0e93863a7c3d90f86beee782f4f3f".toCharArray()));
	}
}
