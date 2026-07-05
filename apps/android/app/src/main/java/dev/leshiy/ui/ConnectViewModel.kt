package dev.leshiy.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.leshiy.data.TunnelRepository
import dev.leshiy.data.UriStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import uniffi.leshiy_mobile.ConnState

data class ConnectUiState(
    val uri: String = "",
    val running: Boolean = false,
    val state: ConnState = ConnState.DISCONNECTED,
    val upBytes: ULong = 0u,
    val downBytes: ULong = 0u,
)

class ConnectViewModel(app: Application) : AndroidViewModel(app) {
    private val store = UriStore(app)
    private val uriFlow = MutableStateFlow("")

    init {
        // Seed the field from the persisted URI once, without clobbering user edits.
        viewModelScope.launch {
            store.lastUri.collect { saved ->
                if (uriFlow.value.isEmpty() && saved.isNotEmpty()) uriFlow.value = saved
            }
        }
    }

    val uiState: StateFlow<ConnectUiState> =
        combine(uriFlow, TunnelRepository.running, TunnelRepository.status) { uri, running, status ->
            ConnectUiState(
                uri = uri,
                running = running,
                state = status?.state ?: ConnState.DISCONNECTED,
                upBytes = status?.upBytes ?: 0u,
                downBytes = status?.downBytes ?: 0u,
            )
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ConnectUiState())

    fun onUriChange(v: String) {
        uriFlow.value = v
    }

    fun currentUri(): String = uriFlow.value.trim()

    fun persist(uri: String) {
        viewModelScope.launch { store.save(uri) }
    }
}
