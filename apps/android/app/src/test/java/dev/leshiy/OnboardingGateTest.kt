package dev.leshiy

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OnboardingGateTest {

    @Test
    fun shows_only_on_fresh_install_not_yet_completed() {
        assertTrue(shouldShowOnboarding(complete = false, hasAnyServer = false))
    }

    @Test
    fun never_shows_once_completed() {
        for (hasServer in listOf(true, false)) {
            assertFalse(shouldShowOnboarding(complete = true, hasAnyServer = hasServer))
        }
    }

    @Test
    fun never_shows_when_a_server_already_exists() {
        // Existing users who updated already have a profile — straight to Connect.
        assertFalse(shouldShowOnboarding(complete = false, hasAnyServer = true))
    }
}
