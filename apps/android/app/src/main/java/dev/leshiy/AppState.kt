package dev.leshiy

import kotlinx.coroutines.flow.MutableStateFlow
import uniffi.leshiy_mobile.Status

// Temporary spike-scoped status holder. Phase 2 replaces this with a proper
// repository + ViewModel fed by the VpnService binding.
object AppState {
    val status = MutableStateFlow<Status?>(null)
    val running = MutableStateFlow(false)
}
