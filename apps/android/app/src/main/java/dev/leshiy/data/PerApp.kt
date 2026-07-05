package dev.leshiy.data

/** Mirrors `leshiy_client::PerAppMode`. Enforced Android-side via the VpnService Builder. */
enum class PerAppMode { OFF, INCLUDE, EXCLUDE }

data class PerAppPlan(val allowed: List<String>, val disallowed: List<String>)

/**
 * Compute the VpnService allow/disallow lists.
 *
 * `selfPkg` must never be tunneled — the app's own dial traffic has to bypass the VPN to avoid a
 * routing loop.
 *
 * - OFF: full tunnel; only this app is excluded.
 * - INCLUDE: only the listed apps are tunneled (`addAllowedApplication`), self dropped. An empty
 *   allow-list would route nothing, so it falls back to OFF semantics.
 * - EXCLUDE: all apps except the listed (plus self) are tunneled (`addDisallowedApplication`).
 */
fun perAppPlan(mode: PerAppMode, packages: Set<String>, selfPkg: String): PerAppPlan = when (mode) {
    PerAppMode.OFF -> PerAppPlan(emptyList(), listOf(selfPkg))
    PerAppMode.INCLUDE -> {
        val allowed = packages.filter { it != selfPkg }
        if (allowed.isEmpty()) PerAppPlan(emptyList(), listOf(selfPkg))
        else PerAppPlan(allowed, emptyList())
    }
    PerAppMode.EXCLUDE -> PerAppPlan(emptyList(), (packages + selfPkg).toList())
}
