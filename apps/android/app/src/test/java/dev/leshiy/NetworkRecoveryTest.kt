package dev.leshiy

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkRecoveryTest {
    @Test fun initial_network_and_duplicate_callbacks_do_not_reconnect() {
        val recovery = NetworkRecovery<String>()
        assertFalse(recovery.available("wifi"))
        assertFalse(recovery.available("wifi"))
    }

    @Test fun direct_replacement_reconnects() {
        val recovery = NetworkRecovery<String>()
        recovery.available("wifi")
        assertTrue(recovery.available("mobile"))
        assertFalse(recovery.available("mobile"))
    }

    @Test fun recovery_after_loss_reconnects_even_on_same_network() {
        for (next in listOf("wifi", "mobile")) {
            val recovery = NetworkRecovery<String>()
            recovery.available("wifi")
            recovery.lost("wifi")
            assertTrue(recovery.available(next))
            assertFalse(recovery.available(next))
        }
    }

    @Test fun late_loss_of_old_network_does_not_invalidate_replacement() {
        val recovery = NetworkRecovery<String>()
        recovery.available("wifi")
        recovery.available("mobile")
        recovery.lost("wifi")
        assertFalse(recovery.available("mobile"))
    }

    @Test fun new_watch_starts_without_previous_session_history() {
        val old = NetworkRecovery<String>()
        old.available("wifi")
        old.lost("wifi")
        assertFalse(NetworkRecovery<String>().available("mobile"))
    }
}
