package com.veggiesnbacon.droidacrypt;

import android.content.Context;
import android.support.annotation.NonNull;
import android.util.Base64;

import javax.crypto.Cipher;

/**
 * Created by Víctor Macías on 11/3/17.
 * Veggies N Bacon
 * victormaciasag@gmail.com
 */

public class AESCryptHelper {

	/**
	 * Decrypts a payload using the master AES key
	 * @param context The application context
	 * @param b64EncryptedPayload Payload bytes coded as a Base64 string
	 * @return Original bytes encoded as a String in UTF-8 encoding
	 */
	public static String getDecryptedPayload(@NonNull Context context, final String b64EncryptedPayload){

		try {

			byte[] plaintBytes = DroidACrypt.getInstance().processSensitivePayload(
					context,
					Cipher.DECRYPT_MODE,
					Base64.decode(b64EncryptedPayload, Base64.DEFAULT)
			);

			return new String(plaintBytes, "UTF-8");

		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;

	}

	/**
	 * Encrypts a payload using the master AES key.
	 * @param context The application context
	 * @param payload The bytes to encrypt
	 * @return The encrypted bytes using the master AES key.
	 */
	public static byte[] encryptPayload(@NonNull Context context, byte[] payload){

		try {

			byte[] encryptedPayload = DroidACrypt.getInstance().processSensitivePayload(
					context,
					Cipher.ENCRYPT_MODE,
					payload
			);

			return encryptedPayload;

		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;

	}


}
