package dev.leshiy

import dev.leshiy.ui.ManageViewModel
import dev.leshiy.ui.ServerStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.leshiy_mobile.ServerInfo

/** Pure state transitions of the Manage drill-down (no FFI/vault involved). */
class ManageStateTest {
    private fun vm(): ManageViewModel = ManageViewModel().apply {
        servers.value = listOf(
            ServerInfo(id = "berlin", label = "Berlin", host = "1.2.3.4", port = 22u, sudo = false, role = "single", downstream = null, hasConnector = false),
        )
    }

    @Test fun select_sets_server_and_resets_transient_state() {
        val v = vm()
        // Dirty the transient state as if we had just visited another server.
        v.status.value = ServerStatus.RUNNING
        v.message.value = "stale error"
        v.select("berlin")
        assertEquals("berlin", v.selected.value)
        assertEquals(ServerStatus.UNKNOWN, v.status.value)
        assertTrue(v.users.value.isEmpty())
        assertNull(v.message.value)
    }

    @Test fun server_info_looks_up_by_id() {
        val v = vm()
        assertEquals("Berlin", v.serverInfo("berlin")?.label)
        assertNull(v.serverInfo("nope"))
    }

    @Test fun present_credential_holds_label_and_uri() {
        val v = vm()
        v.presentCredential("phone", "leshiy://abc")
        assertEquals("phone", v.credential.value?.label)
        assertEquals("leshiy://abc", v.credential.value?.uri)
    }

    @Test fun starts_idle_with_no_pending_action() {
        assertNull(vm().pending.value)
    }
}
