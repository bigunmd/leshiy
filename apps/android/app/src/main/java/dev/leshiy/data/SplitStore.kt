package dev.leshiy.data

import android.content.Context

/** Which split-tunnel scheme is active. The two are mutually exclusive at establish() time. */
enum class SplitKind { APP, NETWORK }

/**
 * Parse "1.2.3.0/24" (or a bare "1.2.3.4", treated as /32 // /128) into `(address, prefixLength)`.
 * Returns null if malformed. Pure — unit-tested.
 */
fun cidrParts(input: String): Pair<String, Int>? {
    val s = input.trim()
    if (s.isEmpty()) return null
    val addr = if ('/' in s) s.substringBefore('/') else s
    val prefixStr = if ('/' in s) s.substringAfter('/') else null
    val isV6 = ':' in addr
    val maxPrefix = if (isV6) 128 else 32
    val prefix = if (prefixStr == null) maxPrefix else (prefixStr.toIntOrNull() ?: return null)
    if (prefix < 0 || prefix > maxPrefix) return null
    if (isV6) {
        // Coarse v6 sanity: hex groups + at least one colon pair.
        if (addr.count { it == ':' } < 2) return null
        if (addr.any { it !in "0123456789abcdefABCDEF:" }) return null
    } else {
        val octets = addr.split('.')
        if (octets.size != 4) return null
        if (octets.any { o -> o.toIntOrNull().let { it == null || it !in 0..255 } }) return null
    }
    return addr to prefix
}

/**
 * Split-tunnel config: which scheme (app vs network) plus the network rules. App rules stay in
 * [PerAppStore]. SharedPreferences — synchronous, so [dev.leshiy.LeshiyVpnService] reads it at
 * establish() time (including always-on start).
 */
class SplitStore(context: Context) {
    private val prefs =
        context.applicationContext.getSharedPreferences("split", Context.MODE_PRIVATE)

    fun kind(): SplitKind =
        runCatching { SplitKind.valueOf(prefs.getString("kind", "APP")!!) }.getOrDefault(SplitKind.APP)

    fun setKind(k: SplitKind) = prefs.edit().putString("kind", k.name).apply()

    fun netMode(): PerAppMode =
        runCatching { PerAppMode.valueOf(prefs.getString("net_mode", "OFF")!!) }.getOrDefault(PerAppMode.OFF)

    fun setNetMode(m: PerAppMode) = prefs.edit().putString("net_mode", m.name).apply()

    fun cidrs(): List<String> =
        (prefs.getStringSet("cidrs", emptySet()) ?: emptySet()).sorted()

    /** Validate + add a CIDR. Returns false if malformed. */
    fun addCidr(input: String): Boolean {
        val parts = cidrParts(input) ?: return false
        val normalized = "${parts.first}/${parts.second}"
        val next = cidrs().toMutableSet().apply { add(normalized) }
        prefs.edit().putStringSet("cidrs", next).apply()
        return true
    }

    fun removeCidr(cidr: String) {
        val next = cidrs().toMutableSet().apply { remove(cidr) }
        prefs.edit().putStringSet("cidrs", next).apply()
    }
}
