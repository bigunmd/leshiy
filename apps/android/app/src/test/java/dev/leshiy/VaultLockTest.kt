package dev.leshiy

import dev.leshiy.data.VAULT_LOCK_MS
import dev.leshiy.data.shouldLockVault
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultLockTest {

    @Test
    fun a_short_absence_keeps_the_vault_open() {
        assertFalse(shouldLockVault(appRelocked = false, elapsedSinceBackgroundMs = 0))
        assertFalse(shouldLockVault(appRelocked = false, elapsedSinceBackgroundMs = VAULT_LOCK_MS - 1))
    }

    @Test
    fun a_long_absence_locks_it_even_without_app_lock() {
        assertTrue(shouldLockVault(appRelocked = false, elapsedSinceBackgroundMs = VAULT_LOCK_MS))
    }

    @Test
    fun an_app_lock_relock_always_locks_it() {
        // Unlocking the app must not hand back SSH credentials that were open before it locked.
        assertTrue(shouldLockVault(appRelocked = true, elapsedSinceBackgroundMs = 0))
    }
}
