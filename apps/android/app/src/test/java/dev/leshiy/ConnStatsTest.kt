package dev.leshiy

import dev.leshiy.ui.Sample
import dev.leshiy.ui.appendSample
import dev.leshiy.ui.shouldSample
import dev.leshiy.ui.throughputRate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.leshiy_mobile.ConnState

class ConnStatsTest {

    @Test
    fun throughput_is_delta_bytes_per_second() {
        // 2000 bytes over 1000 ms = 2000 B/s.
        assertEquals(2000L, throughputRate(prev = 1000u, curr = 3000u, dtMillis = 1000))
        // 500 bytes over 500 ms = 1000 B/s.
        assertEquals(1000L, throughputRate(prev = 0u, curr = 500u, dtMillis = 500))
    }

    @Test
    fun counter_reset_or_no_traffic_is_zero() {
        assertEquals(0L, throughputRate(prev = 5000u, curr = 100u, dtMillis = 1000)) // reset
        assertEquals(0L, throughputRate(prev = 100u, curr = 100u, dtMillis = 1000)) // idle
    }

    @Test
    fun non_positive_dt_is_zero() {
        assertEquals(0L, throughputRate(prev = 0u, curr = 1000u, dtMillis = 0))
    }

    @Test
    fun sampling_is_off_unless_the_user_opted_in() {
        // The graphs are opt-in: with the preference off we do no sampling, however live the
        // tunnel is.
        assertFalse(shouldSample(enabled = false, running = true, state = ConnState.CONNECTED))
    }

    @Test
    fun sampling_needs_a_connected_tunnel() {
        assertTrue(shouldSample(enabled = true, running = true, state = ConnState.CONNECTED))
        assertFalse(shouldSample(enabled = true, running = true, state = ConnState.CONNECTING))
        assertFalse(shouldSample(enabled = true, running = true, state = ConnState.DISCONNECTED))
        assertFalse(shouldSample(enabled = true, running = false, state = ConnState.CONNECTED))
    }

    @Test
    fun append_keeps_only_the_last_max_samples() {
        var h = emptyList<Sample>()
        repeat(65) { i -> h = appendSample(h, Sample(rtt = i, upRate = 0, downRate = 0), max = 60) }
        assertEquals(60, h.size)
        assertEquals(5, h.first().rtt) // 0..4 dropped
        assertEquals(64, h.last().rtt)
    }
}
