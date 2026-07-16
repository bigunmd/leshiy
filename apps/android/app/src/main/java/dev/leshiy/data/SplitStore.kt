package dev.leshiy.data

import android.content.Context

/** Which split-tunnel scheme is active. The two are mutually exclusive at establish() time. */
enum class SplitKind { APP, NETWORK }

private val DOMAIN_RE = Regex("^(\\*\\.)?([a-z0-9-]+\\.)+[a-z]{2,}$", RegexOption.IGNORE_CASE)

/**
 * True for a host like `example.com`, `sub.example.com`, or a `*.example.com` wildcard. Rejects
 * bare IPs (those take the CIDR path) and malformed hosts. Pure — unit-tested.
 */
fun isValidDomain(input: String): Boolean {
    val s = input.trim()
    if (s.isEmpty() || ':' in s) return false
    // An all-numeric-and-dots string is an IP attempt, not a domain.
    if (s.removePrefix("*.").all { it.isDigit() || it == '.' }) return false
    return DOMAIN_RE.matches(s)
}

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
 * Cap on accumulated domain-rule routes. Each is a route on the VPN interface and the accumulated
 * set only grows, so a pathological subscription list — or a CDN with a large address pool — must
 * not bloat the interface without bound. Excess is dropped with a warning, never silently.
 */
const val MAX_DOMAIN_ROUTES = 512

/**
 * Union `current` with `fresh`, capped at [MAX_DOMAIN_ROUTES]. Returns `current` unchanged when
 * nothing new fits, which is the caller's signal not to re-establish.
 *
 * Union rather than replace: on Android every route change costs an interface re-establish (routes
 * are immutable once established), so diffing against a CDN rotating through its pool would churn
 * the tunnel on every refresh, forever. Accumulating converges instead. At the cap, entries
 * already present win over new ones — they are already routed, and evicting one would un-route
 * traffic that is currently working. Pure — unit-tested.
 */
fun mergeDomainRoutes(
    current: Set<Pair<String, Int>>,
    fresh: Set<Pair<String, Int>>,
): Set<Pair<String, Int>> {
    if (current.size >= MAX_DOMAIN_ROUTES) return current
    val out = LinkedHashSet(current)
    for (route in fresh) {
        if (out.size >= MAX_DOMAIN_ROUTES) break
        out.add(route)
    }
    return out
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

    fun domains(): List<String> =
        (prefs.getStringSet("domains", emptySet()) ?: emptySet()).sorted()

    /** Validate + add a domain rule. Returns false if malformed. */
    fun addDomain(input: String): Boolean {
        val d = input.trim().lowercase()
        if (!isValidDomain(d)) return false
        val next = domains().toMutableSet().apply { add(d) }
        prefs.edit().putStringSet("domains", next).apply()
        return true
    }

    fun removeDomain(domain: String) {
        val next = domains().toMutableSet().apply { remove(domain) }
        prefs.edit().putStringSet("domains", next).apply()
    }
}
