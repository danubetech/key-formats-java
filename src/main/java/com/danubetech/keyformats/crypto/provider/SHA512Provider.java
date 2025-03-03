package com.danubetech.keyformats.crypto.provider;

import java.security.GeneralSecurityException;
import java.util.Iterator;
import java.util.ServiceLoader;

public abstract class SHA512Provider {

	private static SHA512Provider instance;

	public static SHA512Provider get() {

		SHA512Provider result = instance;

		if (result == null) {

			synchronized(SHA512Provider.class) {

				result = instance;

				if (result == null) {

					ServiceLoader<SHA512Provider> serviceLoader = ServiceLoader.load(SHA512Provider.class, SHA512Provider.class.getClassLoader());
					Iterator<SHA512Provider> iterator = serviceLoader.iterator();
					if (! iterator.hasNext()) throw new RuntimeException("No " + SHA512Provider.class.getName() + " registered");

					instance = result = iterator.next();
				}
			}
		}

		return result;
	}

	public static void set(SHA512Provider instance) {
		
		SHA512Provider.instance = instance;
	}
	
	public abstract byte[] sha512(byte[] bytes) throws GeneralSecurityException;
}
