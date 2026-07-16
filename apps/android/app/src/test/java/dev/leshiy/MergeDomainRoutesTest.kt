package dev.leshiy

import dev.leshiy.data.MAX_DOMAIN_ROUTES
import dev.leshiy.data.mergeDomainRoutes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The accumulate-don't-replace rule for Android domain-rule routes. Each change to this set costs
 * an interface re-establish, which breaks in-flight connections — so "did the set change?" is the
 * question that decides whether the tunnel gets churned, and it has to be right.
 */
class MergeDomainRoutesTest {

    private fun r(ip: String) = ip to 32

    @Test fun new_addresses_are_added() {
        val merged = mergeDomainRoutes(setOf(r("1.1.1.1")), setOf(r("2.2.2.2")))
        assertEquals(setOf(r("1.1.1.1"), r("2.2.2.2")), merged)
    }

    /**
     * The load-bearing case. A CDN handing back a different slice of its pool must not evict what
     * we already route — that is what would churn the interface on every refresh, forever.
     */
    @Test fun addresses_that_vanish_from_dns_are_kept() {
        val current = setOf(r("1.1.1.1"), r("2.2.2.2"))
        val merged = mergeDomainRoutes(current, setOf(r("3.3.3.3")))
        assertEquals(setOf(r("1.1.1.1"), r("2.2.2.2"), r("3.3.3.3")), merged)
    }

    /**
     * An unchanged resolution must compare equal, because the caller uses exactly that to decide
     * not to re-establish. If this ever returned a fresh-but-equal set the check would still hold
     * (it's `==`, not identity), but a *superset* would silently churn the tunnel every 30 min.
     */
    @Test fun resolving_the_same_addresses_changes_nothing() {
        val current = setOf(r("1.1.1.1"), r("2.2.2.2"))
        assertEquals(current, mergeDomainRoutes(current, setOf(r("2.2.2.2"), r("1.1.1.1"))))
        assertEquals(current, mergeDomainRoutes(current, emptySet()))
    }

    @Test fun merging_into_an_empty_set_takes_everything_fresh() {
        val fresh = setOf(r("1.1.1.1"), r("2.2.2.2"))
        assertEquals(fresh, mergeDomainRoutes(emptySet(), fresh))
    }

    /** v4 and v6 entries coexist; the prefix is part of the identity. */
    @Test fun families_and_prefixes_are_distinct_entries() {
        val merged = mergeDomainRoutes(
            setOf("1.1.1.1" to 32),
            setOf("2606:4700:4700::1111" to 128, "1.1.1.1" to 24),
        )
        assertEquals(3, merged.size)
    }

    @Test fun the_union_is_capped() {
        val current = (0 until MAX_DOMAIN_ROUTES - 1).mapTo(mutableSetOf()) { r("10.0.${it / 256}.${it % 256}") }
        val fresh = setOf(r("8.8.8.8"), r("9.9.9.9"), r("1.1.1.1"))
        val merged = mergeDomainRoutes(current, fresh)
        assertEquals(MAX_DOMAIN_ROUTES, merged.size)
        assertTrue("everything already routed must survive the cap", merged.containsAll(current))
    }

    /**
     * At the cap the caller must see "unchanged" and skip the re-establish — otherwise a full set
     * would re-establish on every single refresh while never actually changing.
     */
    @Test fun a_full_set_is_returned_unchanged_so_no_reestablish_happens() {
        val current = (0 until MAX_DOMAIN_ROUTES).mapTo(mutableSetOf()) { r("10.0.${it / 256}.${it % 256}") }
        val merged = mergeDomainRoutes(current, setOf(r("8.8.8.8")))
        assertSame(current, merged)
        assertEquals(current, merged)
    }
}
