package dev.leshiy

import dev.leshiy.data.LOCK_GRACE_MS
import dev.leshiy.data.shouldLock
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppLockTest {

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
