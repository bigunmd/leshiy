package dev.leshiy

/** What a Quick Settings tile tap should do. Pure decision, kept testable. */
enum class TileVerb { START, STOP, OPEN_APP }

/**
 * Running → stop. Stopped → start directly only when a tap can actually succeed
 * (VPN consent already granted AND an active profile exists); anything else needs
 * the app UI (consent dialog / profile setup), so open it.
 */
fun tileAction(running: Boolean, hasConsent: Boolean, hasProfile: Boolean): TileVerb =
    when {
        running -> TileVerb.STOP
        hasConsent && hasProfile -> TileVerb.START
        else -> TileVerb.OPEN_APP
    }
