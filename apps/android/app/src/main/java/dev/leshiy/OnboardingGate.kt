package dev.leshiy

/**
 * Whether to show first-run onboarding. Pure decision, kept testable — mirrors [tileAction] /
 * [shouldAutoStart].
 *
 * Onboarding is for people who have never used the app: shown only on a fresh install (no server
 * configured) that hasn't yet completed or skipped it. Existing users who updated already have a
 * profile, so they go straight to Connect.
 */
fun shouldShowOnboarding(complete: Boolean, hasAnyServer: Boolean): Boolean =
    !complete && !hasAnyServer
