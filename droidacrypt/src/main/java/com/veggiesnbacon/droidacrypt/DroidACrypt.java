package com.veggiesnbacon.droidacrypt;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.support.annotation.IntDef;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

/**
 *
 * Convenience class to handle cryptographic operations
 * <br>
 * Uses AndroidKeyStore provider if it's available (see {@link Build.VERSION_CODES#JELLY_BEAN_MR2}
 * <br>
 * Created by Víctor Macías on 10/30/17.
 * Veggies N Bacon
 * victormaciasag@gmail.com
 */

public class DroidACrypt {

	private static final String TAG = "DroidACrypt";

	private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
	private static final String ANDROID_OPENSSL = "AndroidOpenSSL";
	private static final String KEY_ALIAS = "RSA_KEY";

	private static final String KEY_ALGORITHM_RSA = "RSA/ECB/PKCS1Padding";
	private static final String AES_CBC_PKCS7_PADDING = "AES/CBC/PKCS7Padding";

	private static final int RSA_KEYSIZE = 2048;
	public static final int AES_IV_SIZE = 16;

	private static DroidACrypt instance;

	private static final SecureRandom secureRandom = new SecureRandom();

	public static SecureRandom getSecureRandom(){
		return secureRandom;
	}

	public static DroidACrypt getInstance(){

		synchronized (DroidACrypt.class){
			if (instance == null){
				instance = new DroidACrypt();
			}
		}

		return instance;

	}

	private DroidACrypt(){

	}

	/**
	 * Check if the Android backed keystore (see {@link #ANDROID_KEY_STORE}) is available to use
	 * @return true if the Android native keystore is available, false otherwise
	 */
	public static boolean isAndroidKeystoreAvailable(){

		return Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2;

	}

	/**
	 * Initializes a keystore and set's an RSA key to use. Finally, sets up an AES Key in the app's
	 * shared preferences with id {@link CryptoConstants#CRYPTO_SHPREFS}, on
	 * {@link CryptoConstants#AES_ENCRYPTED_KEY} field. Once this is done, it is safe to call
	 * {@link DroidACrypt#processSensitivePayload(Context, int, byte[])}
	 *
	 * The RSA key is created with a default key size defined by {@link #RSA_KEYSIZE} where it's
	 * possible.
	 * It is possible to call this method any number of times as it will not recreate the Keystore
	 * or RSA keys if they already exist.
	 * @param appContext Application context to load the Keystore
	 * @return true if the Keystore and keys were properly created, false otherwise
	 */
	public static boolean bootstrap(@NonNull Context appContext){

		try {

			PRNGFixes.apply();

		} catch (SecurityException ex){

			Log.i(TAG, ex.getMessage());

		}


		DroidACrypt droidACrypt = DroidACrypt.getInstance();

		boolean keyStoreInitialized = droidACrypt.initKeystore(appContext);

		if (keyStoreInitialized){

			SharedPreferences prefs = appContext.getSharedPreferences(CryptoConstants.CRYPTO_SHPREFS, Context.MODE_PRIVATE);

			if (!prefs.contains(CryptoConstants.AES_ENCRYPTED_KEY)){

				byte[] encryptedAESBytes = droidACrypt.generateSecretAESKey(appContext, CryptoConstants.AES_KEY_SIZE_BITS);

				String b64EncryptedAES = Base64.encodeToString(encryptedAESBytes, Base64.DEFAULT);

				prefs.edit().putString(CryptoConstants.AES_ENCRYPTED_KEY, b64EncryptedAES).apply();

			}

		}

		return keyStoreInitialized;

	}


	/**
	 * Initializes a keystore and set's an RSA key to use.
	 *
	 * The RSA key is created with a default key size defined by {@link #RSA_KEYSIZE} where it's
	 * possible.
	 * It is possible to call this method any number of times as it will not recreate the Keystore
	 * or RSA keys if they already exist.
	 * @param context Application context to load the Keystore
	 * @return true if the Keystore and key were properly created, false otherwise
	 */
	private boolean initKeystore(@NonNull Context context){

		try {

			KeyStore keyStore = loadKeystore(context);


			if (!keyStore.containsAlias(KEY_ALIAS)) {

				KeyPairGenerator kpg = getKeyPairGenerator(context);

				generateKeyPair(keyStore, kpg);

			}

		} catch (Exception e) {
			e.printStackTrace();

			return false;

		}

		return true;


	}

	/**
	 * Generates a key pair and stores it in the given keystore
	 * @param keyStore The keystore in which the new key will be saved
	 * @param keyPairGenerator The initialized keypair generator (see {@link #getKeyPairGenerator(Context)})
	 * @throws CertificateException If something bad occurs
	 * @throws KeyStoreException If something bad occurs
	 */
	private void generateKeyPair(KeyStore keyStore, KeyPairGenerator keyPairGenerator) throws CertificateException, KeyStoreException {

		KeyPair kpair = keyPairGenerator.generateKeyPair();

	}

	/**
	 * Loads the application's Keystore
	 * @param context Application context to access the keystore if it's persisted in the file system
	 * @return The correctly loaded application's Keystore
	 * @throws GeneralSecurityException If something bad occurs
	 */
	private KeyStore loadKeystore(@NonNull Context context) throws GeneralSecurityException {

		KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);

		try {

			keyStore.load(null);

		} catch (IOException e) {
			throw new GeneralSecurityException("Cannot load Android Keystore", e);
		}

		return keyStore;


	}

	/**
	 * Generates a new cryptographically-secure random AES key of the given keylength. The key
	 * will be encrypted using the public key stored in the device for storage
	 * @param context Application context to retrieve the public key
	 * @param keyLengthBits AES key length, must be 128, 192 or 256.
	 * @return New encrypted random AES key or null if a bad length is provided
	 */
	public byte[] generateSecretAESKey(@NonNull Context context, int keyLengthBits){

		byte[] newSecretAes = null;

		if (keyLengthBits == 128 || keyLengthBits == 192 || keyLengthBits == 256){

			newSecretAes = new byte[keyLengthBits/8];

			secureRandom.nextBytes(newSecretAes);

			try {

				return publicOperation(context, Cipher.ENCRYPT_MODE, newSecretAes);

			} catch (GeneralSecurityException e) {

				e.printStackTrace();

			}

		}

		return newSecretAes;

	}

	@IntDef({
			Cipher.ENCRYPT_MODE,
			Cipher.DECRYPT_MODE
	})
	@Retention(RetentionPolicy.SOURCE)
	public @interface CryptoOperationMode{}

	/**
	 * Retrieve the Public Key for whatever you may want to
	 * @param context Application Context
	 * @return Public Key bytes
	 * @throws GeneralSecurityException if the keystore fails to load
	 */
	public byte[] getPublicKey(@NonNull Context context) throws GeneralSecurityException {

		KeyStore keyStore = loadKeystore(context);

		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);

		PublicKey key = privateKeyEntry.getCertificate().getPublicKey();

		return key.getEncoded();

	}

	/**
	 * Uses the stored public key to perform a cryptographic operation on the provided payload
	 * @param context Application context to retrieve the Keystore
	 * @param operation The operation to be executed, either {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
	 * @param payload The payload to be processed, it must not exceed {@link #RSA_KEYSIZE} or an exception will be thrown
	 * @return Bytes resulting from the operation on the payload
	 * @throws GeneralSecurityException If something bad occurs
	 */

	public byte[] publicOperation(@NonNull Context context, @CryptoOperationMode int operation, @NonNull byte[] payload) throws GeneralSecurityException {

		KeyStore keyStore = loadKeystore(context);

		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);

		Cipher inputCipher = getRSACipher();
		inputCipher.init(operation, privateKeyEntry.getCertificate().getPublicKey());

		byte[] vals = inputCipher.doFinal(payload);

		return vals;

	}

	/**
	 * Uses the stored private key to perform a cryptographic operation on the provided payload
	 * @param context Application context to retrieve the Keystore
	 * @param operation The operation to be executed, either {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
	 * @param payload The payload to be processed, it must not exceed {@link #RSA_KEYSIZE} or an exception will be thrown
	 * @return Bytes resulting from the operation on the payload
	 * @throws GeneralSecurityException If something bad occurs
	 */
	public byte[] privateOperation(@NonNull Context context, @CryptoOperationMode int operation, @NonNull byte[] payload) throws GeneralSecurityException {

		KeyStore keyStore = loadKeystore(context);

		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);

		Cipher inputCipher = getRSACipher();
		inputCipher.init(operation, privateKeyEntry.getPrivateKey());

		byte[] vals = inputCipher.doFinal(payload);

		return vals;

	}

	/**
	 * Initializes an RSA/ECB/PKCS1Padding Cipher for encryption purposes
	 * @return An initialized RSA Cipher
	 */
	private Cipher getRSACipher() {

		try {

			if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2){

				return Cipher.getInstance(KEY_ALGORITHM_RSA);

			} else if (Build.VERSION.SDK_INT < 23) {

				return Cipher.getInstance(KEY_ALGORITHM_RSA, ANDROID_OPENSSL);

			}

			return Cipher.getInstance(KEY_ALGORITHM_RSA);

		} catch(Exception e) {

			throw new RuntimeException("getRSACipher: Failed to get an instance of Cipher", e);

		}
	}

	/**
	 * Initializes an AES/CBC/PCKS5Padding Cipher for encryption purposes
	 * @return An initialized AES Cipher
	 */
	private Cipher getAESCipher(){

		try {

			if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2){

				return Cipher.getInstance(AES_CBC_PKCS7_PADDING);

			} else if (Build.VERSION.SDK_INT < 23) {

				return Cipher.getInstance(AES_CBC_PKCS7_PADDING);

			}

			return Cipher.getInstance(AES_CBC_PKCS7_PADDING);

		} catch (Exception e){

			throw new RuntimeException("getAESCipher: Failed to get an instance of Cipher", e);

		}



	}

	/**
	 * Creates a correctly initialized KeyPairGenerator, according to the current API Level
	 * @return
	 */
	private KeyPairGenerator getKeyPairGenerator(@NonNull Context context) {

		try {

			KeyPairGenerator generator;

			if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2){

				generator = KeyPairGenerator.getInstance("RSA");
				generator.initialize(RSA_KEYSIZE);

			} else {

				if (Build.VERSION.SDK_INT <= 23){

					generator = KeyPairGenerator.getInstance("RSA", ANDROID_KEY_STORE);

				} else {

					generator = KeyPairGenerator.getInstance("RSA");

				}

				Calendar start = Calendar.getInstance();
				Calendar end = Calendar.getInstance();
				end.add(Calendar.YEAR, 30);

				KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
						.setAlias(KEY_ALIAS)
						.setSubject(new X500Principal("C=MX, ST=JAL, O=VeggiesNBacon, CN=VeggiesNBacon"))
						.setSerialNumber(new BigInteger("9290"))
						.setStartDate(start.getTime())
						.setEndDate(end.getTime())
						.build();

				generator.initialize(spec, secureRandom);

			}

			return generator;

		} catch(Exception exception) {

			throw new RuntimeException("getKeyPairGenerator: Failed to get an instance of KeyPairGenerator", exception);

		}
	}

	/**
	 * Process some sensitive bytes. If the operation is decryption, the first 16 bytes should be
	 * the payload's IV followed by the encrypted data. If the operation is encryption, the output
	 * will contain the IV in the first 16 bytes, followed by the encrypted data.
	 * @param context Application context to access the application's keystore
	 * @param operation The operation to be applied, either {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
	 * @param payload The sensitive payload
	 * @return Bytes resulting from the operation, containing either plain data for decryption mode
	 *          or the IV and encrypted data for encryption mode
	 * @throws GeneralSecurityException If something bad occurs
	 */
	public byte[] processSensitivePayload(@NonNull Context context, @CryptoOperationMode int operation, @NonNull byte[] payload) throws GeneralSecurityException {

		SharedPreferences prefs = context.getSharedPreferences(CryptoConstants.CRYPTO_SHPREFS, Context.MODE_PRIVATE);

		String cryptoAES = prefs.getString(CryptoConstants.AES_ENCRYPTED_KEY, null);

		if (cryptoAES == null){
			throw new GeneralSecurityException("No AES card in storage");
		}

		byte[] aesEncrypedBytes = Base64.decode(cryptoAES, Base64.DEFAULT);
		byte[] ivBytes;

		if (operation == Cipher.ENCRYPT_MODE){

			ivBytes = getRandomBytes(AES_IV_SIZE);

		} else {

			ivBytes = new byte[AES_IV_SIZE];
			System.arraycopy(payload, 0, ivBytes, 0, AES_IV_SIZE);

			int realPayloadLength = payload.length- AES_IV_SIZE;
			byte[] nuPayload = new byte[realPayloadLength];

			System.arraycopy(payload, AES_IV_SIZE, nuPayload, 0, realPayloadLength);

			payload = nuPayload;

		}


		byte[] result = aesOperation(context, operation, aesEncrypedBytes, ivBytes, payload);

		if (operation == Cipher.ENCRYPT_MODE){

			byte[] resultWithIV = new byte[result.length + AES_IV_SIZE];

			System.arraycopy(ivBytes, 0, resultWithIV, 0, AES_IV_SIZE);
			System.arraycopy(result, 0, resultWithIV, AES_IV_SIZE, result.length);

			result = resultWithIV;

		}

		return result;

	}

	/**
	 * Processes a payload using the AES encryption algorithm and the AES master key
	 * @param context Application context to access the application's keystore
	 * @param operation The operation to be applied, either {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
	 * @param encryptedKeyBytes The encrypted AES key
	 * @param ivBytes The IV bytes for the supplied payload
	 * @param payloadBytes The payload to be processed
	 * @return Bytes resulting from the operation on the payload
	 * @throws GeneralSecurityException If something bad occurs
	 */
	private byte[] aesOperation(@NonNull Context context, @CryptoOperationMode int operation, @NonNull byte[] encryptedKeyBytes, @NonNull byte[] ivBytes, @NonNull byte[] payloadBytes) throws GeneralSecurityException {

		byte[] aesDecryptedBytes = privateOperation(context, Cipher.DECRYPT_MODE, encryptedKeyBytes);

		SecretKey key = new SecretKeySpec(aesDecryptedBytes, AES_CBC_PKCS7_PADDING);
		IvParameterSpec iv = new IvParameterSpec(ivBytes);

		Cipher cipher = getAESCipher();
		cipher.init(operation, key, iv);

		byte[] result = cipher.doFinal(payloadBytes);

		return result;

	}

	/**
	 * Get cryptographically-secure random bytes
	 * @param byteCount How many bytes do you need?
	 * @return The bytes you need
	 */
	public byte[] getRandomBytes(int byteCount){

		byte[] randomBytes = new byte[byteCount];

		secureRandom.nextBytes(randomBytes);

		return randomBytes;

	}

}
