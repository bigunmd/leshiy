package dev.leshiy

import dev.leshiy.ui.CascadePlan
import dev.leshiy.ui.HopRole
import dev.leshiy.ui.Slot
import dev.leshiy.ui.SlotSource
import dev.leshiy.ui.buildCascades
import dev.leshiy.ui.chainedIds
import dev.leshiy.ui.nextToDeploy
import dev.leshiy.ui.presetFor
import dev.leshiy.ui.resolveDownstream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.leshiy_mobile.ServerInfo

class CascadePlanTest {
    private fun base() = CascadePlan.default()

    @Test fun default_plan_is_entry_then_exit_and_not_ready() {
        val p = base()
        assertEquals(listOf(HopRole.ENTRY, HopRole.EXIT), p.slots.map { it.role })
        assertFalse(p.isReady)
    }

    @Test fun ready_when_all_slots_have_a_source() {
        val p = base().withSource(0, SlotSource.DeployNew).withSource(1, SlotSource.DeployNew)
        assertTrue(p.isReady)
    }

    @Test fun entry_cannot_be_a_pasted_link() {
        val p = base()
            .withSource(0, SlotSource.PasteLink("leshiy://x"))
            .withSource(1, SlotSource.DeployNew)
        assertFalse(p.isReady)
    }

    @Test fun add_middle_inserts_between_entry_and_exit() {
        val p = base().withMiddleAdded()
        assertEquals(listOf(HopRole.ENTRY, HopRole.MIDDLE, HopRole.EXIT), p.slots.map { it.role })
    }

    @Test fun wiring_order_is_exit_first() {
        val p = base().withMiddleAdded()
        assertEquals(listOf(2, 1, 0), p.wiringOrder())
    }
}

class WiringTest {
    private val connectorOf: (String) -> String? = { if (it == "berlin") "leshiy://berlin-conn" else null }

    @Test fun existing_server_resolves_connector_and_id() {
        val w = resolveDownstream(SlotSource.UseExisting("berlin"), null, connectorOf)
        assertEquals("leshiy://berlin-conn", w?.connector)
        assertEquals("berlin", w?.downstreamId)
    }

    @Test fun pasted_link_has_no_id() {
        val w = resolveDownstream(SlotSource.PasteLink("leshiy://ext"), null, connectorOf)
        assertEquals("leshiy://ext", w?.connector)
        assertEquals(null, w?.downstreamId)
    }

    @Test fun deploy_new_resolves_once_deployed_id_known() {
        assertEquals(null, resolveDownstream(SlotSource.DeployNew, null, connectorOf))
        val w = resolveDownstream(SlotSource.DeployNew, "berlin", connectorOf)
        assertEquals("berlin", w?.downstreamId)
        assertEquals("leshiy://berlin-conn", w?.connector)
    }
}

class OrchestrationTest {
    private val connectorOf: (String) -> String? = { if (it == "berlin") "leshiy://berlin-conn" else null }

    @Test fun next_to_deploy_is_exit_first() {
        val plan = CascadePlan.default()
            .withSource(0, SlotSource.DeployNew)
            .withSource(1, SlotSource.DeployNew)
        assertEquals(1, nextToDeploy(plan, emptyMap()))
        assertEquals(0, nextToDeploy(plan, mapOf(1 to "berlin")))
        assertEquals(null, nextToDeploy(plan, mapOf(1 to "berlin", 0 to "riga")))
    }

    @Test fun exit_slot_has_no_downstream_entry_wires_to_exit() {
        val plan = CascadePlan.default()
            .withSource(0, SlotSource.DeployNew)
            .withSource(1, SlotSource.UseExisting("berlin"))
        val exitPreset = presetFor(plan, 1, emptyMap(), connectorOf)
        assertEquals("exit", exitPreset.role)
        assertEquals(null, exitPreset.connector)
        val entryPreset = presetFor(plan, 0, emptyMap(), connectorOf)
        assertEquals("entry", entryPreset.role)
        assertEquals("leshiy://berlin-conn", entryPreset.connector)
        assertEquals("berlin", entryPreset.downstreamId)
    }
}

class BuildCascadesTest {
    private fun srv(id: String, role: String, downstream: String? = null) =
        ServerInfo(
            id = id, label = id, host = "1.1.1.1", port = 443u, sudo = false,
            role = role, downstream = downstream, hasConnector = role == "exit" || role == "middle",
            imageRef = "ghcr.io/bigunmd/leshiy:v1.9.0",
        )

    @Test fun follows_downstream_entry_to_exit() {
        val servers = listOf(
            srv("riga", "entry", "oslo"),
            srv("oslo", "middle", "berlin"),
            srv("berlin", "exit"),
            srv("solo", "single"),
        )
        val chains = buildCascades(servers)
        assertEquals(1, chains.size)
        assertEquals(listOf("riga", "oslo", "berlin"), chains[0].nodes.map { it.server?.id })
        assertEquals(setOf("riga", "oslo", "berlin"), chainedIds(servers))
    }

    @Test fun missing_downstream_is_flagged() {
        val servers = listOf(srv("riga", "entry", "gone"))
        val chain = buildCascades(servers).single()
        assertEquals("riga", chain.nodes[0].server?.id)
        assertEquals("gone", chain.nodes[1].missingId)
    }
}
