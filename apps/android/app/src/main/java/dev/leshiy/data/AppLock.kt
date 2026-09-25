package dev.leshiy.data

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL

/** How long the app may sit in the background before a re-lock is required. */
const val LOCK_GRACE_MS = 30_000L

/**
 * True when the device can satisfy the app-lock — a strong biometric, or (API 30+) a device
 * credential as fallback. Used to refuse enabling the lock on a device with nothing enrolled.
 */
fun biometricAvailable(context: Context): Boolean {
    val authenticators =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) BIOMETRIC_STRONG or DEVICE_CREDENTIAL else BIOMETRIC_STRONG
    return BiometricManager.from(context).canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS
}

/**
 * Whether returning to the foreground should re-lock the UI. Pure, kept testable like [tileAction].
 *
 * A brief background→foreground (switching out to copy a link) stays within [graceMs] and does not
 * re-prompt; a longer absence re-locks. Cold start passes [Long.MAX_VALUE] as the elapsed time, so
 * it always locks when the feature is enabled.
 */
fun shouldLock(
    enabled: Boolean,
    elapsedSinceBackgroundMs: Long,
    graceMs: Long = LOCK_GRACE_MS,
): Boolean = enabled && elapsedSinceBackgroundMs >= graceMs

/**
 * Whether a newly created activity starts behind the lock. A rotation or language change recreates
 * the activity ([recreated]) in the same process, where an unlock already happened — re-prompting
 * then is just noise. After process death the saved state is restored too, but the in-process
 * unlock is gone, so it locks. Pure, like [shouldLock].
 */
fun shouldStartLocked(enabled: Boolean, recreated: Boolean, unlockedInProcess: Boolean): Boolean =
    enabled && !(recreated && unlockedInProcess)

/** How long the app may sit in the background before the server vault is locked again. */
const val VAULT_LOCK_MS = 5 * 60_000L

/**
 * Whether returning to the foreground should lock the server vault. Pure, like [shouldLock].
 *
 * The vault holds SSH credentials for every saved server, so it must not stay open for the
 * process's lifetime — which, with the VPN service keeping the process alive, is indefinitely.
 */
fun shouldLockVault(appRelocked: Boolean, elapsedSinceBackgroundMs: Long): Boolean =
    appRelocked || elapsedSinceBackgroundMs >= VAULT_LOCK_MS
