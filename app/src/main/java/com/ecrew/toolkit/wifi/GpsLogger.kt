package com.ecrew.toolkit.wifi

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Build
import android.os.Bundle
import androidx.core.content.ContextCompat

/**
 * Root-free GPS logger for wardriving. Uses the platform LocationManager
 * (GPS provider preferred, network fallback) - no Play Services, no cloud.
 */
class GpsLogger(context: Context) {

    private val lm =
        context.getSystemService(Context.LOCATION_SERVICE) as LocationManager

    @Volatile
    var last: Location? = null
        private set

    @Volatile
    var running: Boolean = false
        private set

    /** Invoked on the location thread; keep it thread-safe. */
    @Volatile
    var onFix: ((Location) -> Unit)? = null

    private val listener = object : LocationListener {
        override fun onLocationChanged(location: Location) {
            last = location
            onFix?.invoke(location)
        }

        @Deprecated("Deprecated in API")
        override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}
        override fun onProviderEnabled(provider: String) {}
        override fun onProviderDisabled(provider: String) {}
    }

    fun hasPermission(context: Context): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED

    /** @return true if updates were requested. */
    fun start(context: Context): Boolean {
        if (running) return true
        if (!hasPermission(context)) return false
        val provider = when {
            lm.isProviderEnabled(LocationManager.GPS_PROVIDER) -> LocationManager.GPS_PROVIDER
            lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER) -> LocationManager.NETWORK_PROVIDER
            else -> return false
        }
        return try {
            if (Build.VERSION.SDK_INT >= 30) {
                lm.requestLocationUpdates(
                    provider, 2000L, 2f, listener, context.mainLooper
                )
            } else {
                @Suppress("DEPRECATION")
                lm.requestLocationUpdates(provider, 2000L, 2f, listener)
            }
            running = true
            true
        } catch (e: SecurityException) {
            false
        }
    }

    fun stop() {
        if (!running) return
        try {
            lm.removeUpdates(listener)
        } catch (e: Exception) {
            // ignore
        }
        running = false
    }
}

