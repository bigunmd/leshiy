package dev.leshiy.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import dev.leshiy.data.PerAppMode
import dev.leshiy.data.SplitKind
import dev.leshiy.data.SplitStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Owns the split-tunnel scheme (app vs network) and the network CIDR rules. */
class SplitViewModel(app: Application) : AndroidViewModel(app) {
    private val store = SplitStore(app)

    private val _kind = MutableStateFlow(store.kind())
    val kind: StateFlow<SplitKind> = _kind.asStateFlow()

    private val _netMode = MutableStateFlow(store.netMode())
    val netMode: StateFlow<PerAppMode> = _netMode.asStateFlow()

    private val _cidrs = MutableStateFlow(store.cidrs())
    val cidrs: StateFlow<List<String>> = _cidrs.asStateFlow()

    fun setKind(k: SplitKind) {
        store.setKind(k)
        _kind.value = k
    }

    fun setNetMode(m: PerAppMode) {
        store.setNetMode(m)
        _netMode.value = m
    }

    /** Returns false if the CIDR was malformed. */
    fun addCidr(input: String): Boolean {
        val ok = store.addCidr(input)
        if (ok) _cidrs.value = store.cidrs()
        return ok
    }

    fun removeCidr(cidr: String) {
        store.removeCidr(cidr)
        _cidrs.value = store.cidrs()
    }
}
