package com.veggiesnbacon.droidacrypt;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;

import java.util.Map;
import java.util.Set;


/**
 * Created by Víctor Macías on 5/1/18.
 * Pocket de Latinoamérica SAPI de CV
 * vmacias@billpocket.com
 */
public class SharedCryptoPreferences implements SharedPreferences {

	private static final String TAG = "SharedCryptoPreferences";

	private static final String CRYPTO_PREFIX = "DROIDACRYPT_";

	private SharedPreferences shadowPreferences;

	private SharedCryptoPreferences(){

	}

	public static SharedPreferences getInstance(@NonNull Context context, @NonNull String name, int mode){

		SharedPreferences backingPrefs = context.getSharedPreferences(name, mode);

		if (!DroidACrypt.isAndroidKeystoreAvailable()){
			Log.w(TAG, "Regular SharedPreferences created. No Android Keystore Support! Do not store secrets here, they will be stored in plaintext!");
			return backingPrefs;
		}

		SharedCryptoPreferences preferences = new SharedCryptoPreferences();

		preferences.shadowPreferences = backingPrefs;

		return preferences;

	}

	@Override
	public Map<String, ?> getAll() {

		return shadowPreferences.getAll();
	}

	@Nullable
	@Override
	public String getString(String s, @Nullable String s1) {

		return null;
	}

	@Nullable
	@Override
	public Set<String> getStringSet(String s, @Nullable Set<String> set) {

		return null;
	}

	@Override
	public int getInt(String s, int i) {

		return shadowPreferences.getInt(s, i);
	}

	@Override
	public long getLong(String s, long l) {

		return shadowPreferences.getLong(s, l);
	}

	@Override
	public float getFloat(String s, float v) {

		return shadowPreferences.getFloat(s, v);
	}

	@Override
	public boolean getBoolean(String s, boolean b) {

		return shadowPreferences.getBoolean(s, b);
	}

	@Override
	public boolean contains(String s) {

		return shadowPreferences.contains(s);
	}

	@Override
	public Editor edit() {

		return CryptoEditor.newInstance(this);
	}

	@Override
	public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {

		shadowPreferences.registerOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);

	}

	@Override
	public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {

		shadowPreferences.unregisterOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);

	}

	public static class CryptoEditor implements Editor{

		private Editor shadowEditor;

		private CryptoEditor(){

		}

		@SuppressLint("CommitPrefEdits")
		static CryptoEditor newInstance(SharedCryptoPreferences sharedCryptoPreferences){

			CryptoEditor cryptoEditor = new CryptoEditor();

			cryptoEditor.shadowEditor = sharedCryptoPreferences.shadowPreferences.edit();

			return cryptoEditor;

		}

		@Override
		public Editor putString(String s, @Nullable String s1) {

			return null;
		}

		@Override
		public Editor putStringSet(String s, @Nullable Set<String> set) {

			return null;
		}

		@Override
		public Editor putInt(String s, int i) {

			return shadowEditor.putInt(s, i);
		}

		@Override
		public Editor putLong(String s, long l) {

			return shadowEditor.putLong(s, l);
		}

		@Override
		public Editor putFloat(String s, float v) {

			return shadowEditor.putFloat(s, v);
		}

		@Override
		public Editor putBoolean(String s, boolean b) {

			return shadowEditor.putBoolean(s, b);
		}

		@Override
		public Editor remove(String s) {

			return shadowEditor.remove(s);
		}

		@Override
		public Editor clear() {

			return shadowEditor.clear();
		}

		@Override
		public boolean commit() {

			return shadowEditor.commit();
		}

		@Override
		public void apply() {

			shadowEditor.apply();

		}
	}
}
