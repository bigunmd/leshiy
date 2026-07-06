package dev.leshiy

import dev.leshiy.data.cidrParts
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CidrPartsTest {
    @Test fun parses_v4_cidr() {
        assertEquals("10.0.0.0" to 8, cidrParts("10.0.0.0/8"))
    }

    @Test fun bare_v4_is_slash_32() {
        assertEquals("1.2.3.4" to 32, cidrParts("1.2.3.4"))
    }

    @Test fun trims_whitespace() {
        assertEquals("192.168.0.0" to 16, cidrParts("  192.168.0.0/16 "))
    }

    @Test fun rejects_bad_octet() {
        assertNull(cidrParts("999.1.1.1/24"))
    }

    @Test fun rejects_bad_prefix() {
        assertNull(cidrParts("10.0.0.0/33"))
        assertNull(cidrParts("10.0.0.0/x"))
    }

    @Test fun rejects_short_address() {
        assertNull(cidrParts("10.0.0/24"))
    }

    @Test fun parses_v6() {
        assertEquals("2001:db8::" to 32, cidrParts("2001:db8::/32"))
    }

    @Test fun rejects_empty() {
        assertNull(cidrParts("   "))
    }
}
