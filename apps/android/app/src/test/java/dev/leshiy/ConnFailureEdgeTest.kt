package dev.leshiy

import dev.leshiy.data.isFailureEdge
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.leshiy_mobile.ConnState

class ConnFailureEdgeTest {

    @Test
    fun fires_when_entering_failed_from_any_other_state() {
        for (prev in ConnState.values().filter { it != ConnState.FAILED }) {
            assertTrue("edge from $prev", isFailureEdge(prev, ConnState.FAILED))
        }
    }

    @Test
    fun fires_when_entering_failed_from_null_start() {
        assertTrue(isFailureEdge(null, ConnState.FAILED))
    }

    @Test
    fun does_not_refire_while_staying_failed() {
        assertFalse(isFailureEdge(ConnState.FAILED, ConnState.FAILED))
    }

    @Test
    fun never_fires_for_non_failed_targets() {
        val prevs: List<ConnState?> = ConnState.values().toList() + null
        for (next in ConnState.values().filter { it != ConnState.FAILED }) {
            for (prev in prevs) {
                assertFalse("target $next", isFailureEdge(prev, next))
            }
        }
    }
}
