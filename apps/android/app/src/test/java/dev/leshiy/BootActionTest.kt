package dev.leshiy

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BootActionTest {

    @Test
    fun starts_only_when_all_conditions_hold() {
        assertTrue(
            shouldAutoStart(toggleOn = true, hasConsent = true, hasProfile = true, alreadyRunning = false),
        )
    }

    @Test
    fun toggle_off_never_starts() {
        for (consent in listOf(true, false)) for (profile in listOf(true, false)) for (running in listOf(true, false)) {
            assertFalse(
                shouldAutoStart(toggleOn = false, hasConsent = consent, hasProfile = profile, alreadyRunning = running),
            )
        }
    }

    @Test
    fun no_consent_never_starts() {
        assertFalse(
            shouldAutoStart(toggleOn = true, hasConsent = false, hasProfile = true, alreadyRunning = false),
        )
    }

    @Test
    fun no_profile_never_starts() {
        assertFalse(
            shouldAutoStart(toggleOn = true, hasConsent = true, hasProfile = false, alreadyRunning = false),
        )
    }

    @Test
    fun already_running_never_starts() {
        // The system's native always-on VPN already started the tunnel; stand down.
        assertFalse(
            shouldAutoStart(toggleOn = true, hasConsent = true, hasProfile = true, alreadyRunning = true),
        )
    }
}
