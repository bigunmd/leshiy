package dev.leshiy.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import dev.leshiy.data.Profiles
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import uniffi.leshiy_mobile.ProfileInfo

class ProfilesViewModel(app: Application) : AndroidViewModel(app) {
    private val mgr = Profiles.manager(app)
    private val _profiles = MutableStateFlow(mgr.list())
    val profiles: StateFlow<List<ProfileInfo>> = _profiles.asStateFlow()

    private fun refresh() {
        _profiles.value = mgr.list()
    }

    /** Returns false if the URI was invalid (nothing added). */
    fun add(uri: String, name: String): Boolean {
        val ok = runCatching { mgr.add(uri.trim(), name.ifBlank { "Server" }) }.isSuccess
        refresh()
        return ok
    }

    fun remove(id: String) {
        runCatching { mgr.remove(id) }
        refresh()
    }

    fun activate(id: String) {
        runCatching { mgr.setActive(id) }
        refresh()
    }

    fun activeUri(): String? = mgr.activeUri()
}
