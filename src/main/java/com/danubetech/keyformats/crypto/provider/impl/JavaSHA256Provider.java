package com.danubetech.keyformats.crypto.provider.impl;

import com.danubetech.keyformats.crypto.provider.SHA256Provider;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public class JavaSHA256Provider extends SHA256Provider {

	@Override
	public byte[] sha256(byte[] bytes) throws GeneralSecurityException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(bytes);
		return messageDigest.digest();
	}
}
