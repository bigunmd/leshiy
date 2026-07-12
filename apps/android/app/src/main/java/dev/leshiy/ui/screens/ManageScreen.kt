package dev.leshiy.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.data.VaultHolder
import dev.leshiy.ui.ManageViewModel
import dev.leshiy.ui.components.Field
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.Wisp

/** Server list — the entry point of the Manage flow. Tapping a server drills into its detail. */
@Composable
fun ManageScreen(
    vm: ManageViewModel,
    onOpenServer: (String) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val s = LocalStrings.current
    var unlocked by remember { mutableStateOf(VaultHolder.unlocked) }

    // Refresh whenever the screen is shown with an unlocked vault — e.g. after deploying a
    // server, where the vault was already unlocked so the unlock branch below never runs.
    androidx.compose.runtime.LaunchedEffect(unlocked) {
        if (unlocked) vm.refreshServers()
    }

    ScreenFrame(s.manage, onBack = onBack) {
        if (!unlocked) {
            var pass by remember { mutableStateOf("") }
            var failed by remember { mutableStateOf(false) }
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(s.unlockVault, style = MaterialTheme.typography.labelSmall, color = Dim)
                Field(pass, { pass = it; failed = false }, s.vaultPassphrase)
                PrimaryButton(
                    s.unlock,
                    onClick = {
                        if (VaultHolder.unlock(context, pass)) unlocked = true else failed = true
                    },
                    enabled = pass.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (failed) Text(s.wrongPassphrase, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
            }
            return@ScreenFrame
        }

        val servers by vm.servers.collectAsStateWithLifecycle()

        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            item { SectionLabel(s.savedServers) }
            if (servers.isEmpty()) {
                item { Text(s.noSavedServers, style = MaterialTheme.typography.labelSmall, color = Dim) }
            }
            items(servers, key = { it.id }) { server ->
                PanelCard(onClick = { vm.select(server.id); onOpenServer(server.id) }) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(LeshiyIcons.Server, null, tint = Moss, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(server.label, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(server.host, style = MaterialTheme.typography.labelSmall, color = Dim)
                        }
                        Icon(LeshiyIcons.ChevronRight, null, tint = Moss, modifier = Modifier.size(18.dp))
                    }
                }
            }
        }
    }
}
