package com.veggiesnbacon.droidacrypt.application;

import android.app.Application;

import com.veggiesnbacon.droidacrypt.DroidACrypt;

/**
 * Created by Víctor Macías on 5/1/18.
 * Veggies N Bacon
 * victormaciasag@gmail.com
 */
public class DroidaCryptApp extends Application {

	@Override
	public void onCreate() {
		super.onCreate();

		DroidACrypt.bootstrap(this);

	}
}
