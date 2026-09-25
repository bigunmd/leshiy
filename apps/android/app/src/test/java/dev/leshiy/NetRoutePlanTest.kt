package dev.leshiy

import dev.leshiy.data.PerAppMode
import dev.leshiy.data.VPN_DNS
import dev.leshiy.data.netRoutePlan
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetRoutePlanTest {
    private val v4 = "10.0.0.0" to 8
    private val v6 = "2001:db8::" to 32

    @Test
    fun exclude_applies_v4_ranges_without_block_ipv6() {
        val p = netRoutePlan(PerAppMode.EXCLUDE, listOf(v4, v6), blockV6 = false, canExclude = true)
        assertEquals(listOf("0.0.0.0" to 0), p.routes)
        // v6 isn't captured, so it already goes direct; only the v4 range needs excluding.
        assertEquals(listOf(v4), p.excludes)
        assertFalse(p.v6Address)
    }

    @Test
    fun exclude_with_block_ipv6_captures_v6_and_excludes_both_families() {
        val p = netRoutePlan(PerAppMode.EXCLUDE, listOf(v4, v6), blockV6 = true, canExclude = true)
        assertEquals(listOf("0.0.0.0" to 0, "::" to 0), p.routes)
        assertEquals(listOf(v4, v6), p.excludes)
        assertTrue(p.v6Address)
    }

    @Test
    fun exclude_before_android_13_is_a_full_tunnel() {
        val p = netRoutePlan(PerAppMode.EXCLUDE, listOf(v4), blockV6 = false, canExclude = false)
        assertEquals(listOf("0.0.0.0" to 0), p.routes)
        assertTrue(p.excludes.isEmpty())
    }

    @Test
    fun include_routes_listed_ranges_plus_the_vpn_dns_server() {
        val p = netRoutePlan(PerAppMode.INCLUDE, listOf(v4, v6), blockV6 = false, canExclude = true)
        // Without the resolver's route every app's DNS would leave in plaintext, outside the tunnel.
        assertEquals(listOf(v4, v6, VPN_DNS to 32), p.routes)
        assertTrue(p.excludes.isEmpty())
        assertTrue(p.v6Address)
    }

    @Test
    fun include_without_ranges_falls_back_to_full_tunnel() {
        val p = netRoutePlan(PerAppMode.INCLUDE, emptyList(), blockV6 = false, canExclude = true)
        assertEquals(listOf("0.0.0.0" to 0), p.routes)
    }

    @Test
    fun off_is_full_tunnel() {
        val p = netRoutePlan(PerAppMode.OFF, listOf(v4), blockV6 = true, canExclude = true)
        assertEquals(listOf("0.0.0.0" to 0, "::" to 0), p.routes)
        assertTrue(p.excludes.isEmpty())
    }
}
