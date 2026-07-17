package dev.leshiy

import dev.leshiy.ui.StepState
import dev.leshiy.ui.UPGRADE_STEPS
import dev.leshiy.ui.UpgradeState
import dev.leshiy.ui.applyError
import dev.leshiy.ui.applyEvent
import dev.leshiy.ui.canUpgrade
import dev.leshiy.ui.formatElapsed
import dev.leshiy.ui.shortVersion
import dev.leshiy.ui.stepStates
import dev.leshiy.ui.updateAvailable
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpgradeTest {
    private val n = UPGRADE_STEPS.size

    @Test fun steps_start_all_pending() {
        assertEquals(
            List(n) { StepState.PENDING },
            stepStates(n, doneCount = 0, activeIndex = -1, failedIndex = -1),
        )
    }

    @Test fun the_active_step_follows_the_done_ones() {
        assertEquals(
            listOf(StepState.DONE, StepState.ACTIVE, StepState.PENDING, StepState.PENDING),
            stepStates(n, doneCount = 1, activeIndex = 1, failedIndex = -1),
        )
    }

    @Test fun failure_pins_later_steps_to_pending() {
        assertEquals(
            listOf(StepState.DONE, StepState.DONE, StepState.FAILED, StepState.PENDING),
            stepStates(n, doneCount = 2, activeIndex = -1, failedIndex = 2),
        )
    }

    @Test fun completion_marks_every_step_done() {
        assertEquals(
            List(n) { StepState.DONE },
            stepStates(n, doneCount = n, activeIndex = -1, failedIndex = -1),
        )
    }

    @Test fun short_version_reads_the_tag() {
        assertEquals("v1.9.0", shortVersion("ghcr.io/bigunmd/leshiy:v1.9.0"))
    }

    @Test fun short_version_does_not_read_a_registry_port_as_a_tag() {
        assertEquals("localhost:5000/leshiy", shortVersion("localhost:5000/leshiy"))
    }

    @Test fun short_version_leaves_a_digest_ref_whole() {
        val ref = "ghcr.io/bigunmd/leshiy@sha256:0123456789abcdef"
        assertEquals(ref, shortVersion(ref))
    }

    @Test fun update_available_only_when_the_ref_differs() {
        assertFalse(updateAvailable("ghcr.io/o/r:v1.9.0", "ghcr.io/o/r:v1.9.0"))
        assertTrue(updateAvailable("ghcr.io/o/r:v1.8.0", "ghcr.io/o/r:v1.9.0"))
    }

    @Test fun elapsed_formats_as_minutes_and_padded_seconds() {
        assertEquals("0:00", formatElapsed(0))
        assertEquals("0:14", formatElapsed(14_000))
        assertEquals("1:35", formatElapsed(95_000))
    }

    @Test fun started_then_done_advances_and_records_the_duration() {
        val s = UpgradeState(running = true)
            .applyEvent("Connect", "Started", "", nowMs = 1_000)
            .applyEvent("Connect", "Done", "", nowMs = 3_000)
        assertEquals(1, s.doneCount)
        assertEquals(-1, s.activeIndex)
        assertEquals(2_000L, s.stepMs[0])
        assertEquals(2, s.log.size)
    }

    @Test fun a_step_starting_at_timestamp_zero_still_records_its_duration() {
        val s = UpgradeState(running = true)
            .applyEvent("Connect", "Started", "", nowMs = 0)
            .applyEvent("Connect", "Done", "", nowMs = 1_000)
        assertEquals(1_000L, s.stepMs[0])
    }

    @Test fun a_done_with_no_preceding_started_records_no_duration_and_does_not_misattribute() {
        // Connect's Started/Done pair leaves a stale, nonzero activeSince behind. The old
        // scalar-sentinel guard (`activeSince > 0L`) would treat that leftover as if it
        // belonged to RunContainer and record a bogus duration for it.
        val s = UpgradeState(running = true)
            .applyEvent("Connect", "Started", "", nowMs = 1_000)
            .applyEvent("Connect", "Done", "", nowMs = 3_000)
            .applyEvent("RunContainer", "Done", "", nowMs = 5_000)
        assertFalse(s.stepMs.containsKey(2))
    }

    @Test fun a_detail_becomes_the_headline_subtitle() {
        val s = UpgradeState(running = true)
            .applyEvent("PullImage", "Started", "ghcr.io/o/r:v1.9.0", nowMs = 0)
        assertEquals("ghcr.io/o/r:v1.9.0", s.detail)
    }

    @Test fun a_thrown_error_pins_the_failure_to_the_step_in_flight() {
        // engine::upgrade returns Err without ever emitting Failed — the `?` short-circuits — so
        // the in-flight step is the only way to locate where it broke.
        val s = UpgradeState(running = true)
            .applyEvent("Connect", "Started", "", nowMs = 0)
            .applyEvent("Connect", "Done", "", nowMs = 1_000)
            .applyEvent("PullImage", "Started", "ghcr.io/o/r:v1.9.0", nowMs = 1_000)
            .applyError("pull failed: manifest unknown")
        assertFalse(s.running)
        assertEquals("pull failed: manifest unknown", s.error)
        assertEquals(1, s.failedIndex)
        assertEquals(
            listOf(StepState.DONE, StepState.FAILED, StepState.PENDING, StepState.PENDING),
            stepStates(n, s.doneCount, s.activeIndex, s.failedIndex),
        )
    }

    @Test fun an_unknown_step_is_logged_but_advances_nothing() {
        // ProvisionListener is shared with provision, whose step vocabulary is larger.
        val s = UpgradeState(running = true).applyEvent("Firewall", "Started", "", nowMs = 0)
        assertEquals(1, s.log.size)
        assertEquals(-1, s.activeIndex)
        assertEquals(0, s.doneCount)
    }

    @Test fun an_error_with_no_step_in_flight_pins_the_failure_to_the_next_unstarted_step() {
        // engine::upgrade does real work (image ref validation, docker inspect, DNS, port parse)
        // before its first event, so a failure there arrives with activeIndex == -1. The failure
        // must not vanish — it belongs to the next step execution hadn't reached yet.
        val s = UpgradeState(running = true)
            .applyEvent("Connect", "Started", "", nowMs = 0)
            .applyEvent("Connect", "Done", "", nowMs = 1_000)
            .applyError("docker inspect: no such container")
        assertFalse(s.running)
        assertEquals(1, s.failedIndex)
        assertEquals(
            listOf(StepState.DONE, StepState.FAILED, StepState.PENDING, StepState.PENDING),
            stepStates(n, s.doneCount, s.activeIndex, s.failedIndex),
        )
    }

    @Test fun can_upgrade_is_true_for_any_server_when_idle() {
        val s = UpgradeState()
        assertTrue(canUpgrade(s, "berlin"))
        assertTrue(canUpgrade(s, "oslo"))
    }

    @Test fun can_upgrade_is_true_for_the_server_whose_upgrade_is_running() {
        val s = UpgradeState(running = true, serverId = "berlin")
        assertTrue(canUpgrade(s, "berlin"))
    }

    @Test fun can_upgrade_is_false_for_a_different_server_while_one_is_running() {
        val s = UpgradeState(running = true, serverId = "berlin")
        assertFalse(canUpgrade(s, "oslo"))
    }
}
