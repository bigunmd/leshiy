package dev.leshiy.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.leshiy.data.TunnelRepository
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import uniffi.leshiy_mobile.ConnState

data class ConnectUiState(
    val running: Boolean = false,
    val state: ConnState = ConnState.DISCONNECTED,
    val upBytes: ULong = 0u,
    val downBytes: ULong = 0u,
    /** Live keepalive round-trip latency to the server in ms; 0 = unknown. */
    val rttMs: UInt = 0u,
)

/** Observes live tunnel status. The URI to connect comes from the active profile. */
class ConnectViewModel(app: Application) : AndroidViewModel(app) {
    val uiState: StateFlow<ConnectUiState> =
        combine(TunnelRepository.running, TunnelRepository.status) { running, status ->
            ConnectUiState(
                running = running,
                state = status?.state ?: ConnState.DISCONNECTED,
                upBytes = status?.upBytes ?: 0u,
                downBytes = status?.downBytes ?: 0u,
                rttMs = status?.rttMs ?: 0u,
            )
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ConnectUiState())
}
