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

class ManageViewModel : ViewModel() {
    val servers = MutableStateFlow<List<ServerInfo>>(emptyList())
    val users = MutableStateFlow<List<RemoteUserInfo>>(emptyList())
    val selected = MutableStateFlow<String?>(null)
    val busy = MutableStateFlow(false)
    val message = MutableStateFlow<String?>(null)

    // Sudo password for servers provisioned as a non-root user, keyed by server id.
    // Held in memory for the session only — never persisted (matches the vault contract).
    val sudo = MutableStateFlow<Map<String, String>>(emptyMap())

    fun setSudo(id: String, password: String) {
        sudo.value = sudo.value + (id to password)
    }

    /** The sudo password to pass for [id]: a non-blank stored value, else null. */
    private fun sudoFor(id: String): String? = sudo.value[id]?.takeIf { it.isNotBlank() }

    fun refreshServers() {
        servers.value = VaultHolder.get()?.servers() ?: emptyList()
    }

    // ServerManager ops are blocking bridge calls — run them off the main thread.
    private fun op(block: suspend () -> Unit) = viewModelScope.launch {
        busy.value = true
        message.value = null
        runCatching { withContext(Dispatchers.IO) { block() } }
            .onFailure { message.value = it.message ?: "failed" }
        busy.value = false
    }

    /** True when [id] runs privileged ops via sudo but no session password is set yet. */
    fun needsSudo(id: String): Boolean =
        servers.value.firstOrNull { it.id == id }?.sudo == true && sudoFor(id) == null

    fun select(id: String) {
        selected.value = id
        users.value = emptyList()
        // A sudo server can't list users until its password is supplied; wait for it.
        if (!needsSudo(id)) loadUsers(id)
    }

    /** Store the sudo password for [id], then load its users with it. */
    fun submitSudo(id: String, password: String) {
        setSudo(id, password)
        loadUsers(id)
    }

    fun loadUsers(id: String) = op { users.value = VaultHolder.get()!!.listUsers(id, sudoFor(id)) }

    fun addUser(id: String, label: String, onUri: (String) -> Unit) = op {
        val uri = VaultHolder.get()!!.addUser(id, label.ifBlank { "phone" }, sudoFor(id))
        onUri(uri)
        users.value = VaultHolder.get()!!.listUsers(id, sudoFor(id))
    }

    fun deleteUser(id: String, shortId: String) = op {
        VaultHolder.get()!!.deleteUser(id, shortId, sudoFor(id))
        users.value = VaultHolder.get()!!.listUsers(id, sudoFor(id))
    }

    fun status(id: String) = op {
        val up = VaultHolder.get()!!.status(id, sudoFor(id))
        message.value = if (up) "running" else "stopped"
    }

    fun teardown(id: String, purge: Boolean) = op {
        VaultHolder.get()!!.teardown(id, purge, sudoFor(id))
        selected.value = null
        refreshServers()
    }
}
