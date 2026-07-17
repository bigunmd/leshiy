package dev.leshiy

import dev.leshiy.data.shouldPromptBattery
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BatteryPromptTest {

    @Test
    fun prompts_only_when_enabling_keepalive_and_still_restricted() {
        assertTrue(shouldPromptBattery(enablingKeepalive = true, unrestricted = false))
    }

    @Test
    fun no_prompt_when_disabling_keepalive() {
        for (unrestricted in listOf(true, false)) {
            assertFalse(shouldPromptBattery(enablingKeepalive = false, unrestricted = unrestricted))
        }
    }

    @Test
    fun no_prompt_when_already_unrestricted() {
        assertFalse(shouldPromptBattery(enablingKeepalive = true, unrestricted = true))
    }
}
