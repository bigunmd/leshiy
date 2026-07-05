package dev.leshiy.ui

import android.app.Application
import android.content.Intent
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.leshiy.data.PerAppMode
import dev.leshiy.data.PerAppStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
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
        val checked = store.packages()
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
                            checked = pkg in checked,
                        )
                    }.getOrNull()
                }
                .sortedBy { it.label.lowercase() }
        }
        _apps.value = rows
    }

    fun setMode(m: PerAppMode) {
        store.setMode(m)
        _mode.value = m
    }

    fun toggle(pkg: String) {
        store.toggle(pkg)
        load()
    }
}
