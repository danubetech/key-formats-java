package com.danubetech.keyformats.crypto.provider.impl;

import com.danubetech.keyformats.crypto.provider.SHA384Provider;
import com.danubetech.keyformats.crypto.provider.SHA512Provider;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public class JavaSHA512Provider extends SHA512Provider {

	@Override
	public byte[] sha512(byte[] bytes) throws GeneralSecurityException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
		messageDigest.update(bytes);
		return messageDigest.digest();
	}
}
