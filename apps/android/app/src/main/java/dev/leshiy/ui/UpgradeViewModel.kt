package dev.leshiy.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.leshiy.data.VaultHolder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.leshiy_mobile.ProvisionListener
import uniffi.leshiy_mobile.ProvisionUpdate

/**
 * Drives `ServerManager.upgrade` and folds its progress into [UpgradeState].
 *
 * The op runs in `viewModelScope`, so leaving the screen doesn't abandon it — there is no safe
 * interruption point once `docker pull` is running, and killing it mid-recreate is how you end up
 * with a server that has no container.
 */
class UpgradeViewModel : ViewModel() {
    private val _state = MutableStateFlow(UpgradeState())
    val state: StateFlow<UpgradeState> = _state.asStateFlow()

    fun reset() {
        if (!_state.value.running) _state.value = UpgradeState()
    }

    /**
     * [fromRef] and [targetRef] are full image refs; the caller has already resolved the target
     * (an Advanced override, else `defaultImageRef()`), because it needs it to decide whether an
     * update is even available. [mtproxy] also makes the server serve the Telegram proxy.
     */
    fun upgrade(
        serverId: String,
        label: String,
        fromRef: String,
        targetRef: String,
        sudoPassword: String?,
        mtproxy: Boolean,
    ) {
        if (_state.value.running) return
        _state.value = UpgradeState(
            running = true,
            steps = upgradeSteps(mtproxy),
            label = label,
            from = shortVersion(fromRef),
            to = shortVersion(targetRef),
            serverId = serverId,
        )
        viewModelScope.launch {
            val listener = object : ProvisionListener {
                override fun onUpdate(update: ProvisionUpdate) {
                    _state.value = _state.value.applyEvent(
                        update.step,
                        update.status,
                        update.detail,
                        System.currentTimeMillis(),
                    )
                }
            }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    VaultHolder.get()!!.upgrade(serverId, targetRef, sudoPassword, mtproxy, listener)
                }
            }
            result.fold(
                onSuccess = { outcome ->
                    _state.value = _state.value.copy(
                        running = false,
                        done = true,
                        mtproxyLink = outcome.mtproxyLink,
                    )
                },
                onFailure = { e -> _state.value = _state.value.applyError(e.message ?: "failed") },
            )
        }
    }
}
