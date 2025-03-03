package com.danubetech.keyformats.crypto.provider.impl;

import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.crypto.provider.SHA384Provider;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

public class JavaSHA384Provider extends SHA384Provider {

	@Override
	public byte[] sha384(byte[] bytes) throws GeneralSecurityException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-384");
		messageDigest.update(bytes);
		return messageDigest.digest();
	}
}
