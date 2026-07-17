package dev.leshiy

/**
 * Whether a boot / package-replaced broadcast should auto-start the tunnel. Pure decision,
 * kept testable — mirrors [tileAction].
 *
 * Reconnect semantics are "always reconnect when the toggle is on": the toggle *is* the user's
 * intent, so there is no separate last-connected state to track. [alreadyRunning] guards against a
 * double-start when the user *also* enabled Android's native always-on VPN — the OS starts the
 * service on boot, so we stand down. No consent (another app holds always-on) or no active profile
 * both mean a background start could not succeed, so we do nothing rather than fail.
 */
fun shouldAutoStart(
    toggleOn: Boolean,
    hasConsent: Boolean,
    hasProfile: Boolean,
    alreadyRunning: Boolean,
): Boolean = toggleOn && hasConsent && hasProfile && !alreadyRunning
