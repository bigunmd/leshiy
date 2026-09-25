package dev.leshiy.ui

import android.app.Application
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.leshiy.LeshiyVpnService
import dev.leshiy.data.PerAppMode
import dev.leshiy.data.PerAppStore
import dev.leshiy.data.SplitKind
import dev.leshiy.data.SplitStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AppRow(val pkg: String, val label: String, val checked: Boolean)

class AppsViewModel(app: Application) : AndroidViewModel(app) {
    private val store = PerAppStore(app)

    private val _mode = MutableStateFlow(store.mode())
    val mode: StateFlow<PerAppMode> = _mode.asStateFlow()

    private val _apps = MutableStateFlow<List<AppRow>>(emptyList())
    val apps: StateFlow<List<AppRow>> = _apps.asStateFlow()

    init {
        load()
    }

    private fun load() = viewModelScope.launch {
        val self = getApplication<Application>().packageName
        val pm = getApplication<Application>().packageManager
        val rows = withContext(Dispatchers.IO) {
            val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            pm.queryIntentActivities(intent, 0)
                .map { it.activityInfo.packageName }
                .distinct()
                .filter { it != self }
                .mapNotNull { pkg ->
                    runCatching {
                        AppRow(
                            pkg = pkg,
                            label = pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString(),
                            checked = false,
                        )
                    }.getOrNull()
                }
                .sortedBy { it.label.lowercase() }
        }
        // Read the rules only now, so a toggle made while the list was loading is not lost.
        val checked = store.packages()
        _apps.value = rows.map { it.copy(checked = it.pkg in checked) }
    }

    fun setMode(m: PerAppMode) {
        store.setMode(m)
        _mode.value = m
        applyLive()
    }

    /**
     * Flip one app's box in place. Re-querying every installed app per tap was slow, and
     * overlapping reloads could land out of order and show a stale checkbox.
     */
    fun toggle(pkg: String) {
        store.toggle(pkg)
        val checked = pkg in store.packages()
        _apps.update { rows -> rows.map { if (it.pkg == pkg) it.copy(checked = checked) else it } }
        if (store.mode() != PerAppMode.OFF) applyLive()
    }

    /** App rules only shape the tunnel while the app scheme is the active one. */
    private fun applyLive() {
        if (SplitStore(getApplication()).kind() == SplitKind.APP) LeshiyVpnService.reconfigure(getApplication())
    }
}
