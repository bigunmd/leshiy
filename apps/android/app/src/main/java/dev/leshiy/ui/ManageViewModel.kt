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

    fun select(id: String) {
        selected.value = id
        loadUsers(id)
    }

    fun loadUsers(id: String) = op { users.value = VaultHolder.get()!!.listUsers(id, null) }

    fun addUser(id: String, label: String, onUri: (String) -> Unit) = op {
        val uri = VaultHolder.get()!!.addUser(id, label.ifBlank { "phone" }, null)
        onUri(uri)
        users.value = VaultHolder.get()!!.listUsers(id, null)
    }

    fun deleteUser(id: String, shortId: String) = op {
        VaultHolder.get()!!.deleteUser(id, shortId, null)
        users.value = VaultHolder.get()!!.listUsers(id, null)
    }

    fun status(id: String) = op {
        val up = VaultHolder.get()!!.status(id, null)
        message.value = if (up) "running" else "stopped"
    }

    fun teardown(id: String, purge: Boolean) = op {
        VaultHolder.get()!!.teardown(id, purge, null)
        selected.value = null
        refreshServers()
    }
}
