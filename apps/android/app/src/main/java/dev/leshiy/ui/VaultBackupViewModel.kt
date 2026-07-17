package dev.leshiy.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.leshiy.data.VaultHolder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.leshiy_mobile.ImportReport
import uniffi.leshiy_mobile.ServerInfo

/**
 * Export/import of the whole vault. The blob crossing the FFI is ciphertext, and the file itself is
 * the screen's business: SAF hands back a `content://` URI, which only the ContentResolver can open.
 */
class VaultBackupViewModel : ViewModel() {
    val servers = MutableStateFlow<List<ServerInfo>>(emptyList())
    val pending = MutableStateFlow<String?>(null)
    val message = MutableStateFlow<String?>(null)
    val report = MutableStateFlow<ImportReport?>(null)

    fun refreshServers() {
        servers.value = VaultHolder.get()?.servers() ?: emptyList()
    }

    // Argon2 (64 MiB, t=3) makes both ops slow enough to matter, so they run off the main thread.
    private fun op(token: String, block: suspend () -> Unit) = viewModelScope.launch {
        pending.value = token
        message.value = null
        runCatching { withContext(Dispatchers.IO) { block() } }
            .onFailure { message.value = it.message ?: "failed" }
        pending.value = null
    }

    /** Seal the vault under [pass], then hand the ciphertext to [write] (the SAF sink). */
    fun export(pass: String, write: suspend (ByteArray) -> Unit, onDone: () -> Unit) = op("export") {
        val blob = VaultHolder.get()!!.exportBackup(pass)
        write(blob)
        withContext(Dispatchers.Main) { onDone() }
    }

    /** Merge a backup blob into the vault and publish what changed. */
    fun import(bytes: ByteArray, pass: String) = op("import") {
        // Drop any earlier summary first: on failure the assignment below never runs, and a stale
        // "imported N servers" sitting next to the new error would claim a success that didn't
        // happen.
        report.value = null
        report.value = VaultHolder.get()!!.importBackup(bytes, pass)
        refreshServers()
    }

    /** Surface a failure the screen hit on its own (reading the picked file). */
    fun fail(e: Throwable) {
        message.value = e.message ?: "failed"
    }
}
