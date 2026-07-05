package dev.leshiy.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import dev.leshiy.data.VaultHolder
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.leshiy_mobile.ProvisionConfig
import uniffi.leshiy_mobile.ProvisionListener
import uniffi.leshiy_mobile.ProvisionUpdate
import uniffi.leshiy_mobile.Provisioner

data class ProvisionState(
    val running: Boolean = false,
    val log: List<String> = emptyList(),
    val resultUri: String? = null,
    val error: String? = null,
)

class ProvisionViewModel(app: Application) : AndroidViewModel(app) {
    private val _state = MutableStateFlow(ProvisionState())
    val state: StateFlow<ProvisionState> = _state.asStateFlow()

    fun provision(
        host: String,
        sshUser: String,
        sshPassword: String,
        dest: String,
        listenPort: Int,
        onDone: (String) -> Unit,
    ) {
        if (_state.value.running) return
        _state.value = ProvisionState(running = true)
        viewModelScope.launch {
            val cfg = ProvisionConfig(
                host = host.trim(),
                sshPort = 22u,
                sshUser = sshUser.trim().ifBlank { "root" },
                sshPassword = sshPassword,
                dest = dest.trim(),
                listenPort = listenPort.toUShort(),
                label = null,
                sudoPassword = null,
            )
            val listener = object : ProvisionListener {
                override fun onUpdate(update: ProvisionUpdate) {
                    _state.value = _state.value.copy(
                        log = _state.value.log + "${update.step}/${update.status}  ${update.detail}",
                    )
                }
            }
            // provision() is a blocking bridge call — run it off the main thread. When the vault
            // is unlocked, provision through it so the server record is saved for management.
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    VaultHolder.get()?.provision(cfg, listener)
                        ?: Provisioner().provision(cfg, listener)
                }
            }
            result.fold(
                onSuccess = { uri ->
                    _state.value = _state.value.copy(running = false, resultUri = uri)
                    onDone(uri)
                },
                onFailure = { e ->
                    _state.value = _state.value.copy(running = false, error = e.message ?: "failed")
                },
            )
        }
    }
}
