package dev.leshiy.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
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
import dev.leshiy.ui.components.IconBtn
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.Wisp

@Composable
fun ManageScreen(
    vm: ManageViewModel,
    onUserUri: (String, String) -> Unit,
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
                Text(
                    s.unlockVault,
                    style = MaterialTheme.typography.labelSmall,
                    color = Dim,
                )
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
        val users by vm.users.collectAsStateWithLifecycle()
        val selected by vm.selected.collectAsStateWithLifecycle()
        val busy by vm.busy.collectAsStateWithLifecycle()
        val message by vm.message.collectAsStateWithLifecycle()
        val sudoPw by vm.sudo.collectAsStateWithLifecycle()

        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            message?.let { m -> item { Text(m, color = Moss, style = MaterialTheme.typography.labelSmall) } }
            if (servers.isEmpty()) {
                item {
                    Text(
                        s.noSavedServers,
                        style = MaterialTheme.typography.labelSmall,
                        color = Dim,
                    )
                }
            }
            items(servers, key = { it.id }) { server ->
                val open = server.id == selected
                PanelCard(onClick = { vm.select(server.id) }) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(LeshiyIcons.Server, null, tint = if (open) Wisp else Moss, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(server.label, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(server.host, style = MaterialTheme.typography.labelSmall, color = Dim)
                        }
                        Icon(if (open) LeshiyIcons.ChevronDown else LeshiyIcons.ChevronRight, null, tint = Moss, modifier = Modifier.size(18.dp))
                    }

                    // A sudo-user server needs its sudo password before any day-2 op works.
                    val sudoGate = open && server.sudo && sudoPw[server.id].isNullOrBlank()

                    if (sudoGate) {
                        Spacer(Modifier.size(12.dp))
                        SectionLabel(s.sudoPasswordManage)
                        Text(s.sudoRequiredNote, style = MaterialTheme.typography.labelSmall, color = Dim)
                        Spacer(Modifier.size(8.dp))
                        var pw by remember(server.id) { mutableStateOf("") }
                        Field(pw, { pw = it }, s.sudoPasswordManage)
                        Spacer(Modifier.size(10.dp))
                        PrimaryButton(
                            s.sudoApply,
                            onClick = { vm.submitSudo(server.id, pw) },
                            enabled = pw.isNotBlank() && !busy,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }

                    if (open && !sudoGate) {
                        Spacer(Modifier.size(12.dp))
                        SectionLabel(s.users)
                        users.forEach { u ->
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                                Column(Modifier.weight(1f)) {
                                    Text(u.label ?: s.orphan, style = MaterialTheme.typography.bodyMedium, color = if (u.enabled) MaterialTheme.colorScheme.onBackground else MaterialTheme.colorScheme.error)
                                    Text(u.shortId, style = MaterialTheme.typography.labelSmall, color = Dim)
                                }
                                IconBtn(LeshiyIcons.Trash, s.remove, tint = MaterialTheme.colorScheme.error) { vm.deleteUser(server.id, u.shortId) }
                            }
                        }
                        Spacer(Modifier.size(8.dp))
                        var label by remember(server.id) { mutableStateOf("") }
                        Field(
                            label, { label = it }, s.newUserLabel,
                            trailing = { IconBtn(LeshiyIcons.Plus, s.newUserLabel, tint = Wisp) { vm.addUser(server.id, label) { uri -> onUserUri(uri, label.ifBlank { "phone" }); label = "" } } },
                        )
                        Spacer(Modifier.size(10.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            SmallAction(s.checkStatus, enabled = !busy) { vm.status(server.id) }
                            SmallAction(s.teardown, enabled = !busy, danger = true) { vm.teardown(server.id, false) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SmallAction(text: String, enabled: Boolean, danger: Boolean = false, onClick: () -> Unit) {
    androidx.compose.material3.Surface(
        onClick = onClick,
        enabled = enabled,
        shape = androidx.compose.foundation.shape.RoundedCornerShape(10.dp),
        color = androidx.compose.ui.graphics.Color.Transparent,
        border = androidx.compose.foundation.BorderStroke(1.dp, if (danger) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.outline),
    ) {
        Text(
            text,
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
            style = MaterialTheme.typography.labelLarge,
            color = if (danger) MaterialTheme.colorScheme.error else Wisp,
        )
    }
}
