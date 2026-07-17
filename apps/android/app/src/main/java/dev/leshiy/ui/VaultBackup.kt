package dev.leshiy.ui

import dev.leshiy.ui.i18n.Strings
import uniffi.leshiy_mobile.ImportReport
import java.time.LocalDate

/** Export form state: the backup passphrase typed twice, and how many servers would be sealed. */
data class ExportForm(
    val pass: String = "",
    val confirm: String = "",
    val serverCount: Int = 0,
) {
    /** True once a confirmation has been typed and diverges — shown inline, not on submit. */
    val mismatch: Boolean get() = confirm.isNotEmpty() && pass != confirm

    /**
     * A backup passphrase has nothing to check it against later, so a typo produces a permanently
     * unreadable file. Both fields must agree, and an empty vault has nothing worth sealing.
     */
    val ready: Boolean get() = pass.isNotBlank() && pass == confirm && serverCount > 0
}

/** Default name offered to the file picker, e.g. `leshiy-backup-2026-07-17.lvault`. */
fun backupFileName(today: LocalDate): String = "leshiy-backup-$today.lvault"

/** What the merge did, in the user's language. */
fun importSummary(s: Strings, r: ImportReport): String =
    if (r.replaced == 0u) s.importedServers.format(r.added.toInt())
    else s.importedServersReplaced.format(r.added.toInt(), r.replaced.toInt())
