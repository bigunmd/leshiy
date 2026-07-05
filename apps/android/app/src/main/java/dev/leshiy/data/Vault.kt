package dev.leshiy.data

import android.content.Context
import uniffi.leshiy_mobile.ServerManager
import java.io.File

/**
 * Session-held, unlocked [ServerManager]. Null until the user enters the vault passphrase; the
 * SSH secrets live only inside the encrypted vault file (`servers.vault`), never in Kotlin.
 */
object VaultHolder {
    @Volatile
    private var sm: ServerManager? = null

    val unlocked: Boolean get() = sm != null

    fun get(): ServerManager? = sm

    /** Open (or create) the vault under [passphrase]. Returns true on success. */
    fun unlock(context: Context, passphrase: String): Boolean = try {
        val path = File(context.applicationContext.filesDir, "servers.vault").absolutePath
        sm = ServerManager.open(path, passphrase)
        true
    } catch (e: Exception) {
        sm = null
        false
    }

    fun lock() {
        sm = null
    }
}
