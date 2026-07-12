package dev.leshiy.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.leshiy.data.VaultHolder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.leshiy_mobile.RemoteUserInfo
import uniffi.leshiy_mobile.ServerInfo

/** Container run-state for the selected server, driven by "Check status". */
enum class ServerStatus { UNKNOWN, RUNNING, STOPPED, ERROR }

/** A credential to present as QR + copyable link. */
data class Credential(val label: String, val uri: String)

class ManageViewModel : ViewModel() {
    val servers = MutableStateFlow<List<ServerInfo>>(emptyList())
    val users = MutableStateFlow<List<RemoteUserInfo>>(emptyList())
    val selected = MutableStateFlow<String?>(null)
    val status = MutableStateFlow(ServerStatus.UNKNOWN)
    val credential = MutableStateFlow<Credential?>(null)
    val message = MutableStateFlow<String?>(null)

    // Token of the remote op currently in flight (e.g. "status", "addUser", "teardown",
    // "delete:<shortId>"), or null when idle. The UI spins the matching control only.
    val pending = MutableStateFlow<String?>(null)

    // Sudo password for servers provisioned as a non-root user, keyed by server id. Held in
    // memory for the session only — never persisted (matches the vault contract).
    val sudo = MutableStateFlow<Map<String, String>>(emptyMap())

    fun setSudo(id: String, password: String) {
        sudo.value = sudo.value + (id to password)
    }

    /** The sudo password to pass for [id]: a non-blank stored value, else null. */
    private fun sudoFor(id: String): String? = sudo.value[id]?.takeIf { it.isNotBlank() }

    fun refreshServers() {
        servers.value = VaultHolder.get()?.servers() ?: emptyList()
    }

    fun serverInfo(id: String): ServerInfo? = servers.value.firstOrNull { it.id == id }

    /** True when [id] runs privileged ops via sudo but no session password is set yet. */
    fun needsSudo(id: String): Boolean =
        serverInfo(id)?.sudo == true && sudoFor(id) == null

    /** Enter a server's management context: remember it and reset transient state. */
    fun select(id: String) {
        selected.value = id
        users.value = emptyList()
        status.value = ServerStatus.UNKNOWN
        message.value = null
    }

    /** Store the sudo password for [id] so subsequent ops can use it. */
    fun submitSudo(id: String, password: String) {
        setSudo(id, password)
        message.value = null
    }

    fun presentCredential(label: String, uri: String) {
        credential.value = Credential(label, uri)
    }

    // Runs a blocking ServerManager op off the main thread, tagging it with [token] so the UI
    // can show a spinner on exactly the control that triggered it.
    private fun op(token: String, block: suspend () -> Unit) = viewModelScope.launch {
        pending.value = token
        message.value = null
        runCatching { withContext(Dispatchers.IO) { block() } }
            .onFailure { message.value = it.message ?: "failed" }
        pending.value = null
    }

    fun loadUsers(id: String) = op("loadUsers") { users.value = VaultHolder.get()!!.listUsers(id, sudoFor(id)) }

    fun addUser(id: String, label: String, onCreated: (Credential) -> Unit) = op("addUser") {
        val name = label.ifBlank { "phone" }
        val uri = VaultHolder.get()!!.addUser(id, name, sudoFor(id))
        users.value = VaultHolder.get()!!.listUsers(id, sudoFor(id))
        withContext(Dispatchers.Main) { onCreated(Credential(name, uri)) }
    }

    fun deleteUser(id: String, shortId: String) = op("delete:$shortId") {
        VaultHolder.get()!!.deleteUser(id, shortId, sudoFor(id))
        users.value = VaultHolder.get()!!.listUsers(id, sudoFor(id))
    }

    fun checkStatus(id: String) = viewModelScope.launch {
        pending.value = "status"
        message.value = null
        runCatching { withContext(Dispatchers.IO) { VaultHolder.get()!!.status(id, sudoFor(id)) } }
            .onSuccess { up -> status.value = if (up) ServerStatus.RUNNING else ServerStatus.STOPPED }
            .onFailure { status.value = ServerStatus.ERROR; message.value = it.message ?: "failed" }
        pending.value = null
    }

    fun teardown(id: String, purge: Boolean, onDone: () -> Unit) = op("teardown") {
        VaultHolder.get()!!.teardown(id, purge, sudoFor(id))
        selected.value = null
        refreshServers()
        withContext(Dispatchers.Main) { onDone() }
    }
}
