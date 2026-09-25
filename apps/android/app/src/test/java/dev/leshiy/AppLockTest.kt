package dev.leshiy

import dev.leshiy.data.LOCK_GRACE_MS
import dev.leshiy.data.shouldLock
import dev.leshiy.data.shouldStartLocked
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppLockTest {

    @Test
    fun a_configuration_change_keeps_an_unlocked_app_unlocked() {
        assertFalse(shouldStartLocked(enabled = true, recreated = true, unlockedInProcess = true))
    }

    @Test
    fun a_cold_start_or_process_death_restore_starts_locked() {
        // After process death the saved state survives but the unlock does not.
        assertTrue(shouldStartLocked(enabled = true, recreated = true, unlockedInProcess = false))
        assertTrue(shouldStartLocked(enabled = true, recreated = false, unlockedInProcess = true))
        assertFalse(shouldStartLocked(enabled = false, recreated = false, unlockedInProcess = false))
    }

    @Test
    fun disabled_never_locks() {
        assertFalse(shouldLock(enabled = false, elapsedSinceBackgroundMs = Long.MAX_VALUE))
        assertFalse(shouldLock(enabled = false, elapsedSinceBackgroundMs = 0))
    }

    @Test
    fun within_grace_does_not_relock() {
        assertFalse(shouldLock(enabled = true, elapsedSinceBackgroundMs = 0))
        assertFalse(shouldLock(enabled = true, elapsedSinceBackgroundMs = LOCK_GRACE_MS - 1))
    }

    @Test
    fun past_grace_relocks() {
        assertTrue(shouldLock(enabled = true, elapsedSinceBackgroundMs = LOCK_GRACE_MS))
        assertTrue(shouldLock(enabled = true, elapsedSinceBackgroundMs = LOCK_GRACE_MS + 1))
    }

    @Test
    fun cold_start_always_locks_when_enabled() {
        assertTrue(shouldLock(enabled = true, elapsedSinceBackgroundMs = Long.MAX_VALUE))
    }
}
