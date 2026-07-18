package dev.leshiy.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.leshiy.data.AppPrefs
import dev.leshiy.data.TunnelRepository
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
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

    private val _history = MutableStateFlow<List<Sample>>(emptyList())

    /** Rolling one-minute window of live stats for the Connect-screen sparklines. */
    val history: StateFlow<List<Sample>> = _history.asStateFlow()

    /** User opt-in for the Connect-screen graphs (off by default). */
    val liveStats: StateFlow<Boolean> = AppPrefs.liveStatsFlow

    init {
        // Sample on a fixed 1s tick so throughput is a clean per-second rate and the sparkline has
        // an even time axis; drop the whole window whenever we're not sampling (opted out, or the
        // tunnel isn't connected).
        viewModelScope.launch {
            var prevUp = 0uL
            var prevDown = 0uL
            var haveBaseline = false
            while (true) {
                delay(SAMPLE_MS)
                val st = TunnelRepository.status.value
                if (st == null || !shouldSample(liveStats.value, TunnelRepository.running.value, st.state)) {
                    if (_history.value.isNotEmpty()) _history.value = emptyList()
                    haveBaseline = false
                    continue
                }
                val upRate = if (haveBaseline) throughputRate(prevUp, st.upBytes, SAMPLE_MS) else 0L
                val downRate = if (haveBaseline) throughputRate(prevDown, st.downBytes, SAMPLE_MS) else 0L
                prevUp = st.upBytes
                prevDown = st.downBytes
                haveBaseline = true
                _history.value = appendSample(
                    _history.value,
                    Sample(st.rttMs.toInt(), upRate, downRate),
                    MAX_SAMPLES,
                )
            }
        }
    }
}
