package dev.leshiy.data

import android.content.Context
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import uniffi.leshiy_mobile.ServerManager
import java.io.File

/**
 * Session-held, unlocked [ServerManager]. Null until the user enters the vault passphrase; the
 * SSH secrets live only inside the encrypted vault file (`servers.vault`), never in Kotlin.
 * Locked again after [VAULT_LOCK_MS] in the background (see [shouldLockVault]).
 */
object VaultHolder {
    @Volatile
    private var sm: ServerManager? = null

    private val _unlocked = MutableStateFlow(false)

    /** Observed by the vault screens and view models, so a lock sends them back to the gate. */
    val unlockedFlow: StateFlow<Boolean> = _unlocked.asStateFlow()

    val unlocked: Boolean get() = sm != null

    fun get(): ServerManager? = sm

    /**
     * Open (or create) the vault under [passphrase]. Returns true on success. Runs on IO: the key
     * derivation is Argon2 at 64 MiB / t=3, which froze the UI when run on the main thread.
     */
    suspend fun unlock(context: Context, passphrase: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val path = File(context.applicationContext.filesDir, "servers.vault").absolutePath
            sm = ServerManager.open(path, passphrase)
            _unlocked.value = true
            true
        } catch (e: Exception) {
            sm = null
            _unlocked.value = false
            false
        }
    }

    /**
     * Drop the decrypted vault. `destroy()` frees the native side — secrets included — as soon as
     * any call still in flight on it returns, rather than whenever the GC gets round to it.
     */
    fun lock() {
        mainHandler.removeCallbacks(lockNow)
        val old = sm ?: return
        sm = null
        _unlocked.value = false
        old.destroy()
    }

    private val mainHandler = Handler(Looper.getMainLooper())
    private val lockNow = Runnable { lock() }

    /**
     * Lock after [VAULT_LOCK_MS] unless [cancelScheduledLock] comes first. Uptime-based, so it
     * stalls while the device sleeps; the foreground check via [shouldLockVault] covers that.
     */
    fun scheduleLock() {
        mainHandler.removeCallbacks(lockNow)
        if (sm != null) mainHandler.postDelayed(lockNow, VAULT_LOCK_MS)
    }

    fun cancelScheduledLock() {
        mainHandler.removeCallbacks(lockNow)
    }
}
