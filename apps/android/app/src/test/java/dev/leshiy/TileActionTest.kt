package dev.leshiy

import org.junit.Assert.assertEquals
import org.junit.Test

class TileActionTest {

    @Test
    fun running_always_stops() {
        for (consent in listOf(true, false)) for (profile in listOf(true, false)) {
            assertEquals(TileVerb.STOP, tileAction(running = true, hasConsent = consent, hasProfile = profile))
        }
    }

    @Test
    fun stopped_with_consent_and_profile_starts() {
        assertEquals(TileVerb.START, tileAction(running = false, hasConsent = true, hasProfile = true))
    }

    @Test
    fun stopped_without_consent_opens_app() {
        assertEquals(TileVerb.OPEN_APP, tileAction(running = false, hasConsent = false, hasProfile = true))
    }

    @Test
    fun stopped_without_profile_opens_app() {
        assertEquals(TileVerb.OPEN_APP, tileAction(running = false, hasConsent = true, hasProfile = false))
        assertEquals(TileVerb.OPEN_APP, tileAction(running = false, hasConsent = false, hasProfile = false))
    }
}
