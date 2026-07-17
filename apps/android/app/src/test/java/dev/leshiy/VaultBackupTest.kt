package dev.leshiy

import dev.leshiy.ui.ExportForm
import dev.leshiy.ui.backupFileName
import dev.leshiy.ui.i18n.EnStrings
import dev.leshiy.ui.importSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.leshiy_mobile.ImportReport
import java.time.LocalDate

/** Pure export/import helpers (no FFI, no vault). */
class VaultBackupTest {
    @Test fun ready_needs_a_matching_non_blank_passphrase() {
        assertFalse("blank", ExportForm("", "", 1).ready)
        assertFalse("unconfirmed", ExportForm("pw", "", 1).ready)
        assertFalse("typo", ExportForm("pw", "pwx", 1).ready)
        assertTrue(ExportForm("pw", "pw", 1).ready)
    }

    /** A valid-but-empty backup is a trap: it restores nothing and still looks like it worked. */
    @Test fun an_empty_vault_cannot_be_exported() {
        assertFalse(ExportForm("pw", "pw", 0).ready)
    }

    @Test fun mismatch_stays_quiet_until_the_confirm_field_is_typed_in() {
        assertFalse("nothing typed yet", ExportForm("pw", "", 1).mismatch)
        assertTrue("diverging", ExportForm("pw", "p", 1).mismatch)
        assertFalse("matching", ExportForm("pw", "pw", 1).mismatch)
    }

    @Test fun backup_file_name_carries_the_date() {
        assertEquals("leshiy-backup-2026-07-17.lvault", backupFileName(LocalDate.of(2026, 7, 17)))
    }

    @Test fun summary_reports_added_only() {
        assertEquals("Imported 3 servers", importSummary(EnStrings, ImportReport(3u, 0u)))
    }

    @Test fun summary_reports_replacements_too() {
        assertEquals(
            "Imported 3 servers (1 replaced an existing record)",
            importSummary(EnStrings, ImportReport(3u, 1u)),
        )
    }
}
