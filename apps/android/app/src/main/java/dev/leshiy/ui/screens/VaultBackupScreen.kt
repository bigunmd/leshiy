package dev.leshiy.ui.screens

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.data.VaultHolder
import dev.leshiy.ui.ExportForm
import dev.leshiy.ui.VaultBackupViewModel
import dev.leshiy.ui.backupFileName
import dev.leshiy.ui.components.Field
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.importSummary
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Warn
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDate

/** The picker's own name for a document — `lastPathSegment` is an opaque id like `msf:1000`. */
private fun displayName(context: Context, uri: Uri): String =
    context.contentResolver
        .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        ?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
        ?: uri.lastPathSegment.orEmpty()

/**
 * Export the whole vault to a file sealed under a chosen passphrase, and import one back.
 *
 * Both halves need an unlocked vault. On a fresh phone the unlock gate simply creates an empty
 * vault under a new device passphrase, which import then merges into.
 */
@Composable
fun VaultBackupScreen(vm: VaultBackupViewModel, onBack: () -> Unit) {
    val context = LocalContext.current
    val s = LocalStrings.current
    val scope = rememberCoroutineScope()
    var unlocked by remember { mutableStateOf(VaultHolder.unlocked) }

    LaunchedEffect(unlocked) { if (unlocked) vm.refreshServers() }

    ScreenFrame(s.vaultBackup, onBack = onBack) {
        if (!unlocked) {
            var pass by remember { mutableStateOf("") }
            var failed by remember { mutableStateOf(false) }
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(s.unlockVault, style = MaterialTheme.typography.labelSmall, color = Dim)
                Field(pass, { pass = it; failed = false }, s.vaultPassphrase)
                PrimaryButton(
                    s.unlock,
                    onClick = { if (VaultHolder.unlock(context, pass)) unlocked = true else failed = true },
                    enabled = pass.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (failed) {
                    Text(s.wrongPassphrase, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                }
            }
            return@ScreenFrame
        }

        val servers by vm.servers.collectAsStateWithLifecycle()
        val pending by vm.pending.collectAsStateWithLifecycle()
        val message by vm.message.collectAsStateWithLifecycle()
        val report by vm.report.collectAsStateWithLifecycle()

        var pass by remember { mutableStateOf("") }
        var confirm by remember { mutableStateOf("") }
        var exported by remember { mutableStateOf(false) }
        val form = ExportForm(pass, confirm, servers.size)

        // The picker names the file; the seal and the write happen on its callback.
        val exportLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument("application/octet-stream"),
        ) { uri ->
            if (uri != null) vm.export(
                pass = pass,
                write = { bytes ->
                    context.contentResolver.openOutputStream(uri)!!.use { it.write(bytes) }
                },
                onDone = { exported = true; pass = ""; confirm = "" },
            )
        }

        var importBytes by remember { mutableStateOf<ByteArray?>(null) }
        var importName by remember { mutableStateOf("") }
        var importPass by remember { mutableStateOf("") }
        val importLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.OpenDocument(),
        ) { uri ->
            if (uri != null) scope.launch {
                runCatching {
                    withContext(Dispatchers.IO) {
                        val bytes = context.contentResolver.openInputStream(uri)!!.use { it.readBytes() }
                        bytes to displayName(context, uri)
                    }
                }.onSuccess { (bytes, name) ->
                    importBytes = bytes
                    importName = name
                    vm.report.value = null
                }
            }
        }

        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            SectionLabel(s.secExport)
            PanelCard {
                Text(s.exportWarning, style = MaterialTheme.typography.labelSmall, color = Warn)
            }
            if (servers.isEmpty()) {
                Text(s.noServersToExport, style = MaterialTheme.typography.labelSmall, color = Dim)
            } else {
                Field(pass, { pass = it; exported = false }, s.backupPassphrase)
                Field(confirm, { confirm = it; exported = false }, s.confirmBackupPassphrase)
                if (form.mismatch) {
                    Text(s.passphraseMismatch, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                }
                PrimaryButton(
                    s.exportAction,
                    onClick = { exportLauncher.launch(backupFileName(LocalDate.now())) },
                    enabled = form.ready && pending == null,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (exported) Text(s.exportDone, style = MaterialTheme.typography.labelSmall, color = Dim)
            }

            Spacer(Modifier.size(6.dp))
            SectionLabel(s.secImport)
            PrimaryButton(
                s.chooseBackupFile,
                onClick = { importLauncher.launch(arrayOf("*/*")) },
                enabled = pending == null,
                modifier = Modifier.fillMaxWidth(),
            )
            importBytes?.let { bytes ->
                Text(importName, style = MaterialTheme.typography.labelSmall, color = Dim)
                Field(importPass, { importPass = it }, s.backupPassphrase)
                PrimaryButton(
                    s.importAction,
                    onClick = { vm.import(bytes, importPass) },
                    enabled = importPass.isNotBlank() && pending == null,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            report?.let {
                Text(importSummary(s, it), style = MaterialTheme.typography.labelSmall, color = Dim)
            }
            message?.let {
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}
