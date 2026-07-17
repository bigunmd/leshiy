package dev.leshiy

import dev.leshiy.data.fastestReachable
import dev.leshiy.data.hostPort
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PingTest {

    @Test
    fun parses_host_and_port_from_a_leshiy_uri() {
        assertEquals("1.2.3.4" to 443, hostPort("leshiy://abc@1.2.3.4:443?sni=x&sid=0102030400000000"))
        assertEquals("example.com" to 8443, hostPort("leshiy://pk@example.com:8443"))
    }

    @Test
    fun parses_bracketed_ipv6() {
        assertEquals("2001:db8::1" to 443, hostPort("leshiy://pk@[2001:db8::1]:443?sni=x"))
    }

    @Test
    fun rejects_malformed_uris() {
        assertNull("wrong scheme", hostPort("https://1.2.3.4:443"))
        assertNull("no port", hostPort("leshiy://pk@1.2.3.4"))
        assertNull("no authority", hostPort("leshiy://"))
        assertNull("bad port", hostPort("leshiy://pk@host:notaport"))
    }

    @Test
    fun fastest_picks_min_latency_ignoring_unreachable() {
        val r = mapOf("a" to 120L, "b" to 42L, "c" to null, "d" to 300L)
        assertEquals("b", fastestReachable(r))
    }

    @Test
    fun fastest_is_null_when_all_unreachable_or_empty() {
        assertNull(fastestReachable(mapOf("a" to null, "b" to null)))
        assertNull(fastestReachable(emptyMap()))
    }
}
