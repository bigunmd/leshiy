package dev.leshiy.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.leshiy.data.fastestReachable
import dev.leshiy.data.hostPort
import dev.leshiy.data.tcpLatency
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import uniffi.leshiy_mobile.ProfileInfo

/** Per-server latency measurement state. */
sealed interface Latency {
    data object Pinging : Latency
    data class Reachable(val ms: Long) : Latency
    data object Unreachable : Latency
}

/** Measures TCP-connect latency to each saved server. Results fill in progressively. */
class LatencyViewModel : ViewModel() {
    private val _results = MutableStateFlow<Map<String, Latency>>(emptyMap())
    val results: StateFlow<Map<String, Latency>> = _results.asStateFlow()

    fun ping(profiles: List<ProfileInfo>) {
        if (profiles.isEmpty()) return
        _results.value = profiles.associate { it.id to Latency.Pinging }
        for (p in profiles) {
            viewModelScope.launch(Dispatchers.IO) {
                val ms = hostPort(p.uri)?.let { (host, port) -> tcpLatency(host, port, TIMEOUT_MS) }
                val result = ms?.let { Latency.Reachable(it) } ?: Latency.Unreachable
                _results.update { it + (p.id to result) }
            }
        }
    }

    /** Id of the fastest reachable server, per the latest results. */
    fun fastestId(): String? =
        fastestReachable(_results.value.mapValues { (_, v) -> (v as? Latency.Reachable)?.ms })

    private companion object {
        const val TIMEOUT_MS = 2000
    }
}
