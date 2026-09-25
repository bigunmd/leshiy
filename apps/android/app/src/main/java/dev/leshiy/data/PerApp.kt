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
 *
 * Packages failing [isInstalled] are dropped first: the Builder rejects them, and an INCLUDE list
 * of only since-uninstalled apps would otherwise allow nothing — tunneling every app, self included.
 */
fun perAppPlan(
    mode: PerAppMode,
    packages: Set<String>,
    selfPkg: String,
    isInstalled: (String) -> Boolean = { true },
): PerAppPlan {
    val present = packages.filter { it != selfPkg && isInstalled(it) }
    return when (mode) {
        PerAppMode.OFF -> PerAppPlan(emptyList(), listOf(selfPkg))
        PerAppMode.INCLUDE ->
            if (present.isEmpty()) PerAppPlan(emptyList(), listOf(selfPkg))
            else PerAppPlan(present, emptyList())
        PerAppMode.EXCLUDE -> PerAppPlan(emptyList(), present + selfPkg)
    }
}
