package com.veggiesnbacon.droidacrypt;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Base64;

import java.io.UnsupportedEncodingException;

/**
 * Created by Víctor Macías on 12/6/17.
 * Veggies N Bacon
 * victormaciasag@gmail.com
 */

public class CryptoPreferences {

	public static final String CRYPTO_PREFS_NAME = "CRYPTO_PREFS";

	private Context context;
	private SharedPreferences cryptedPreferences;


	public CryptoPreferences(@NonNull Context context){
		this.context = context;
		cryptedPreferences = context.getSharedPreferences(CRYPTO_PREFS_NAME, Context.MODE_PRIVATE);

	}

	/**
	 * Gets a plain string value from encrypted storage, or from plain storage when AndroidKeyStore
	 * is not available, stored using {@link #saveString(String, String, String)}
	 * @param cryptoKey SharedPreferences key to the encrypted value
	 * @param plainKey SharedPreferences key to the plain value, when falling back to plain storage
	 * @param defaultValue Default value in case the provided keys don't match any of the stored ones
	 * @return Plain string for the given keys
	 */
	public String getString(@NonNull String cryptoKey, @NonNull String plainKey, @Nullable String defaultValue){


		String encryptedValue = cryptedPreferences.getString(cryptoKey, null);
		String decryptedValue = defaultValue;


		if (encryptedValue != null){

			if (DroidACrypt.isAndroidKeystoreAvailable()){

				decryptedValue = AESCryptHelper.getDecryptedPayload(context, encryptedValue);

			}

		} else {

			decryptedValue = cryptedPreferences.getString(plainKey, decryptedValue);

		}


		return decryptedValue;

	}

	/**
	 * Save a String value on encrypted storage, if AndroidKeyStore is no available, it will be
	 * stored in plaintext
	 * @param cryptoKey SharedPreferences key to store the encrypted value
	 * @param plainKey SharedPreferences key to store the plain value, when falling back to plain
	 *                 storage
	 * @param value The String value to save
	 * @return true if the value was stored securely, false if stored in plain storage
	 * @throws UnsupportedEncodingException
	 */
	public boolean saveString(@NonNull String cryptoKey, @NonNull String plainKey, @NonNull String value) throws UnsupportedEncodingException {


		if (DroidACrypt.isAndroidKeystoreAvailable()){

			// We have Android KeyStore available so let's encrypt the thing

			byte[] payloadBytes = value.getBytes("UTF-8");

			String encryptedPayload = Base64.encodeToString(
					AESCryptHelper.encryptPayload(context, payloadBytes),
					Base64.DEFAULT
			);

			cryptedPreferences.edit().putString(cryptoKey, encryptedPayload).apply();
			cryptedPreferences.edit().remove(plainKey).apply();

			return true;

		}

		cryptedPreferences.edit().putString(plainKey, value).apply();

		return false;

	}

}
