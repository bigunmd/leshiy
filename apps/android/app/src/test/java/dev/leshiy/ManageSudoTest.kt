package dev.leshiy

import dev.leshiy.ui.ManageViewModel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.leshiy_mobile.ServerInfo

/** The sudo-gating logic that decides when Manage must prompt for a sudo password. */
class ManageSudoTest {
    private fun vmWithServers(): ManageViewModel = ManageViewModel().apply {
        servers.value = listOf(
            ServerInfo(id = "berlin", label = "Berlin", host = "1.2.3.4", port = 22u, sudo = true),
            ServerInfo(id = "oslo", label = "Oslo", host = "5.6.7.8", port = 22u, sudo = false),
        )
    }

    @Test fun sudo_server_needs_password_until_supplied() {
        val vm = vmWithServers()
        assertTrue("sudo server with no password must gate", vm.needsSudo("berlin"))
        vm.setSudo("berlin", "secret")
        assertFalse("password supplied — no longer gated", vm.needsSudo("berlin"))
    }

    @Test fun root_server_never_gates() {
        assertFalse(vmWithServers().needsSudo("oslo"))
    }

    @Test fun blank_password_does_not_satisfy_gate() {
        val vm = vmWithServers()
        vm.setSudo("berlin", "   ")
        assertTrue("a blank password must not unlock management", vm.needsSudo("berlin"))
    }

    @Test fun unknown_server_does_not_gate() {
        assertFalse(vmWithServers().needsSudo("nope"))
    }

    @Test fun set_sudo_is_per_server() {
        val vm = vmWithServers()
        vm.setSudo("berlin", "a")
        assertEquals("a", vm.sudo.value["berlin"])
        assertNull(vm.sudo.value["oslo"])
    }
}
