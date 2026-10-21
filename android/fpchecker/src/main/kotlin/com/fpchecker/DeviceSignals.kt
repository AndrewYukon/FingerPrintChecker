package com.fpchecker

import android.annotation.SuppressLint
import android.content.Context
import android.media.MediaDrm
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import java.util.TimeZone
import java.util.UUID

/** Reads raw platform values. Every read is isolated: a failure yields null, never an exception. */
internal object DeviceSignals {
    private val WIDEVINE_UUID = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

    fun read(context: Context): RawSignals {
        val telephony = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        return RawSignals(
            androidId = androidId(context),
            mediaDrmId = mediaDrmDeviceId(),
            simCountry = safe { telephony?.simCountryIso },
            networkCountry = safe { telephony?.networkCountryIso },
            timezone = safe { TimeZone.getDefault().id },
            buildFingerprint = safe { Build.FINGERPRINT },
            hardware = safe { Build.HARDWARE },
            sdkInt = Build.VERSION.SDK_INT,
            model = safe { Build.MODEL },
        )
    }

    // The per-app-signing-key ANDROID_ID is the documented identity signal of this protocol;
    // the HardwareIds lint rule targets non-resettable hardware serials, not this value.
    @SuppressLint("HardwareIds")
    private fun androidId(context: Context): String? =
        safe { Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) }

    /** Raw Widevine device-unique id. It is hashed in [ComponentRules] and never leaves the device. */
    private fun mediaDrmDeviceId(): ByteArray? {
        var drm: MediaDrm? = null
        return try {
            drm = MediaDrm(WIDEVINE_UUID)
            drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
        } catch (_: Exception) {
            null
        } finally {
            release(drm)
        }
    }

    private fun release(drm: MediaDrm?) {
        if (drm == null) return
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                drm.close()
            } else {
                @Suppress("DEPRECATION") // release() is the only option below API 28
                drm.release()
            }
        } catch (_: Exception) {
            // Nothing useful to do; the session is gone either way.
        }
    }

    private inline fun <T> safe(block: () -> T?): T? = try {
        block()
    } catch (_: Exception) {
        null
    }
}
