package dev.leshiy.data

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Per-app split-tunnel rules in SharedPreferences. Synchronous by design — [LeshiyVpnService]
 * reads them at `establish()` time (including on always-on start, where no coroutine scope exists).
 */
class PerAppStore(context: Context) {
    private val prefs =
        context.applicationContext.getSharedPreferences("perapp", Context.MODE_PRIVATE)

    private val _rules = MutableStateFlow(read())
    val rulesFlow: StateFlow<Pair<PerAppMode, Set<String>>> = _rules.asStateFlow()

    private fun read(): Pair<PerAppMode, Set<String>> {
        val mode = runCatching { PerAppMode.valueOf(prefs.getString("mode", "OFF")!!) }
            .getOrDefault(PerAppMode.OFF)
        return mode to (prefs.getStringSet("pkgs", emptySet()) ?: emptySet())
    }

    fun mode(): PerAppMode = _rules.value.first
    fun packages(): Set<String> = _rules.value.second

    fun setMode(m: PerAppMode) {
        prefs.edit().putString("mode", m.name).apply()
        _rules.value = read()
    }

    fun toggle(pkg: String) {
        val next = packages().toMutableSet().apply { if (!add(pkg)) remove(pkg) }
        prefs.edit().putStringSet("pkgs", next).apply()
        _rules.value = read()
    }
}
