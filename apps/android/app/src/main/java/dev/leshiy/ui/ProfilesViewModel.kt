package dev.leshiy.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.leshiy.data.Profiles
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import uniffi.leshiy_mobile.ProfileInfo
import uniffi.leshiy_mobile.ProfileManager

/**
 * The saved servers. Every [ProfileManager] call crosses into Rust and may write the profile file,
 * so none runs on the main thread. Each change and the list read after it hold one fair lock,
 * taken in tap order on main, so rapid taps can never publish a stale list.
 */
class ProfilesViewModel(app: Application) : AndroidViewModel(app) {
    private val _profiles = MutableStateFlow<List<ProfileInfo>>(emptyList())
    val profiles: StateFlow<List<ProfileInfo>> = _profiles.asStateFlow()

    private val inOrder = Mutex()

    init {
        update({})
    }

    /** [onResult] gets false if the URI was invalid (nothing added). */
    fun add(uri: String, name: String, onResult: (Boolean) -> Unit = {}) =
        update({ it.add(uri.trim(), name.ifBlank { "Server" }) }, onResult)

    fun remove(id: String) = update({ it.remove(id) })

    fun activate(id: String) = update({ it.setActive(id) })

    private fun update(change: (ProfileManager) -> Unit, onResult: (Boolean) -> Unit = {}) =
        viewModelScope.launch {
            inOrder.withLock {
                val (ok, list) = withContext(Dispatchers.IO) {
                    val mgr = Profiles.manager(getApplication())
                    runCatching { change(mgr) }.isSuccess to mgr.list()
                }
                _profiles.value = list
                onResult(ok)
            }
        }
}
