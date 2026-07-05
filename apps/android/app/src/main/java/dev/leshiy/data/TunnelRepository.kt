package dev.leshiy.data

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import uniffi.leshiy_mobile.Status

/**
 * Single source of truth for live tunnel status, pushed from [dev.leshiy.LeshiyVpnService] and
 * observed by the UI. Process-scoped singleton (one VPN session per process).
 */
object TunnelRepository {
    private val _status = MutableStateFlow<Status?>(null)
    val status: StateFlow<Status?> = _status.asStateFlow()

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    fun onStatus(s: Status) {
        _status.value = s
    }

    fun setRunning(v: Boolean) {
        _running.value = v
        if (!v) _status.value = null
    }
}
