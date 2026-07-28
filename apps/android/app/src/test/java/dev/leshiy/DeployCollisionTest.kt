package dev.leshiy

import dev.leshiy.ui.deployCollision
import dev.leshiy.ui.vaultIdFor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.leshiy_mobile.ServerInfo

private fun srv(
    id: String,
    label: String = id,
    host: String = "1.1.1.1",
    role: String = "single",
    downstream: String? = null,
) = ServerInfo(
    id = id, label = label, host = host, port = 443u, sudo = false,
    role = role, downstream = downstream, hasConnector = role == "exit" || role == "middle",
    imageRef = "ghcr.io/bigunmd/leshiy:v1.11.1",
)

class VaultIdTest {
    /** Must mirror `build_params` in crates/leshiy-mobile/src/provision.rs verbatim. */
    @Test fun id_is_host_dash_ssh_port() {
        assertEquals("10.0.0.7-22", vaultIdFor("10.0.0.7", 22))
        assertEquals("example.com-2222", vaultIdFor("example.com", 2222))
    }

    @Test fun host_is_trimmed_like_the_deploy_form_does() {
        assertEquals("10.0.0.7-22", vaultIdFor("  10.0.0.7 ", 22))
    }
}

class DeployCollisionTest {
    @Test fun no_collision_for_an_unseen_host() {
        val saved = listOf(srv("10.0.0.1-22"), srv("10.0.0.2-22"))
        assertNull(deployCollision(saved, "10.0.0.3", 22))
    }

    @Test fun collision_when_host_and_ssh_port_match_an_existing_record() {
        val saved = listOf(srv("10.0.0.2-22", label = "Oslo", role = "exit"))
        val c = deployCollision(saved, "10.0.0.2", 22)
        assertEquals("10.0.0.2-22", c?.existingId)
        assertEquals("Oslo", c?.existingLabel)
        assertEquals("exit", c?.existingRole)
    }

    /** A different SSH port yields a different vault id, so it is genuinely a different record. */
    @Test fun no_collision_when_only_the_ssh_port_differs() {
        val saved = listOf(srv("10.0.0.2-22"))
        assertNull(deployCollision(saved, "10.0.0.2", 2222))
    }

    /**
     * The case this bug is about: IPA (entry) chains to IPB (exit). Re-deploying IPB as a
     * standalone server replaces the exit record, and IPA's `downstream` is left dangling — the
     * cascade and the standalone server become indistinguishable in the vault view.
     */
    @Test fun collision_reports_servers_that_chain_to_the_record() {
        val saved = listOf(
            srv("10.0.0.2-22", label = "Oslo", role = "exit"),
            srv("10.0.0.1-22", label = "Riga", role = "entry", downstream = "10.0.0.2-22"),
        )
        val c = deployCollision(saved, "10.0.0.2", 22)
        assertEquals(listOf("Riga"), c?.chainedFrom)
        assertTrue(c!!.breaksCascade)
    }

    @Test fun a_standalone_record_with_no_dependents_does_not_break_a_cascade() {
        val saved = listOf(srv("10.0.0.2-22", label = "Oslo", role = "single"))
        val c = deployCollision(saved, "10.0.0.2", 22)
        assertEquals(emptyList<String>(), c?.chainedFrom)
        assertTrue(!c!!.breaksCascade)
    }

    /** Every upstream that references the record is listed, not just the first. */
    @Test fun all_dependents_are_listed() {
        val saved = listOf(
            srv("10.0.0.3-22", label = "Exit", role = "exit"),
            srv("10.0.0.1-22", label = "Riga", role = "entry", downstream = "10.0.0.3-22"),
            srv("10.0.0.2-22", label = "Berlin", role = "middle", downstream = "10.0.0.3-22"),
        )
        val c = deployCollision(saved, "10.0.0.3", 22)
        assertEquals(listOf("Riga", "Berlin"), c?.chainedFrom)
    }

    @Test fun an_empty_vault_never_collides() {
        assertNull(deployCollision(emptyList(), "10.0.0.1", 22))
    }

    @Test fun blank_host_never_collides() {
        val saved = listOf(srv("-22", label = "weird"))
        assertNull(deployCollision(saved, "   ", 22))
    }
}
