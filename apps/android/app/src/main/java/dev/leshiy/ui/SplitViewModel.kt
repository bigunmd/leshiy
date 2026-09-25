package dev.leshiy.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import dev.leshiy.LeshiyVpnService
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

    private val _domains = MutableStateFlow(store.domains())
    val domains: StateFlow<List<String>> = _domains.asStateFlow()

    fun setKind(k: SplitKind) {
        store.setKind(k)
        _kind.value = k
        LeshiyVpnService.reconfigure(getApplication())
    }

    fun setNetMode(m: PerAppMode) {
        store.setNetMode(m)
        _netMode.value = m
        if (store.kind() == SplitKind.NETWORK) LeshiyVpnService.reconfigure(getApplication())
    }

    /** Add an IP/CIDR or a domain, auto-detected. Returns false if it's neither. */
    fun addEntry(input: String): Boolean = addQuietly(input).also { if (it) rulesChanged() }

    /** Add many entries (a rule file), applying them to the tunnel once. Returns how many were valid. */
    fun importEntries(lines: Sequence<String>): Int =
        lines.count { addQuietly(it) }.also { if (it > 0) rulesChanged() }

    fun removeCidr(cidr: String) {
        store.removeCidr(cidr)
        _cidrs.value = store.cidrs()
        rulesChanged()
    }

    fun removeDomain(domain: String) {
        store.removeDomain(domain)
        _domains.value = store.domains()
        rulesChanged()
    }

    private fun addQuietly(input: String): Boolean {
        if (store.addCidr(input)) {
            _cidrs.value = store.cidrs()
            return true
        }
        if (store.addDomain(input)) {
            _domains.value = store.domains()
            return true
        }
        return false
    }

    /** Rules only shape the tunnel while the network scheme is active and not OFF. */
    private fun rulesChanged() {
        if (store.kind() == SplitKind.NETWORK && store.netMode() != PerAppMode.OFF) {
            LeshiyVpnService.reconfigure(getApplication())
        }
    }
}
