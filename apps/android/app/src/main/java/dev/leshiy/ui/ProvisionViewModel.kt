package dev.leshiy.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.leshiy.data.VaultHolder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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
    /** Highest engine step reached (-1 before start); drives the progress bar. */
    val stepIndex: Int = -1,
    /** Server label for the resulting profile. */
    val label: String = "",
)

class ProvisionViewModel(app: Application) : AndroidViewModel(app) {
    private val _state = MutableStateFlow(ProvisionState())
    val state: StateFlow<ProvisionState> = _state.asStateFlow()

    fun reset() {
        if (!_state.value.running) _state.value = ProvisionState()
    }

    fun provision(cfg: ProvisionConfig, label: String) {
        if (_state.value.running) return
        _state.value = ProvisionState(running = true, label = label)
        viewModelScope.launch {
            val listener = object : ProvisionListener {
                override fun onUpdate(update: ProvisionUpdate) {
                    val idx = STEPS.indexOf(update.step)
                    _state.value = _state.value.copy(
                        log = _state.value.log + "${update.step}/${update.status}  ${update.detail}",
                        stepIndex = maxOf(_state.value.stepIndex, idx),
                    )
                }
            }
            // Routes through the unlocked vault (saved for management) when available.
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    VaultHolder.get()?.provision(cfg, listener)
                        ?: Provisioner().provision(cfg, listener)
                }
            }
            result.fold(
                onSuccess = { uri ->
                    _state.value = _state.value.copy(running = false, resultUri = uri, stepIndex = STEPS.size)
                },
                onFailure = { e ->
                    _state.value = _state.value.copy(running = false, error = e.message ?: "failed")
                },
            )
        }
    }

    companion object {
        // Engine step order (leshiy_provision::engine::Step) — used for the progress bar.
        private val STEPS = listOf(
            "Connect", "Preflight", "DockerReady", "Firewall", "DetectExisting",
            "PullImage", "RunContainer", "IssueUser", "Persist",
        )
        val TOTAL_STEPS = STEPS.size
    }
}
