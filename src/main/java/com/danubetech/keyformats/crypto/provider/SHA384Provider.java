package com.danubetech.keyformats.crypto.provider;

import java.security.GeneralSecurityException;
import java.util.Iterator;
import java.util.ServiceLoader;

public abstract class SHA384Provider {

	private static SHA384Provider instance;

	public static SHA384Provider get() {

		SHA384Provider result = instance;

		if (result == null) {

			synchronized(SHA384Provider.class) {

				result = instance;

				if (result == null) {

					ServiceLoader<SHA384Provider> serviceLoader = ServiceLoader.load(SHA384Provider.class, SHA384Provider.class.getClassLoader());
					Iterator<SHA384Provider> iterator = serviceLoader.iterator();
					if (! iterator.hasNext()) throw new RuntimeException("No " + SHA384Provider.class.getName() + " registered");

					instance = result = iterator.next();
				}
			}
		}

		return result;
	}

	public static void set(SHA384Provider instance) {
		
		SHA384Provider.instance = instance;
	}
	
	public abstract byte[] sha384(byte[] bytes) throws GeneralSecurityException;
}
