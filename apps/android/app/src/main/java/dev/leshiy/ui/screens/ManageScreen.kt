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
    var unlocked by remember { mutableStateOf(VaultHolder.unlocked) }

    ScreenFrame("Manage servers", onBack = onBack) {
        if (!unlocked) {
            var pass by remember { mutableStateOf("") }
            var failed by remember { mutableStateOf(false) }
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "Unlock the server vault — an encrypted store holding SSH credentials for the servers you provision. Set a passphrase the first time; enter it to unlock later.",
                    style = MaterialTheme.typography.labelSmall,
                    color = Dim,
                )
                Field(pass, { pass = it; failed = false }, "Vault passphrase")
                PrimaryButton(
                    "Unlock",
                    onClick = {
                        if (VaultHolder.unlock(context, pass)) { unlocked = true; vm.refreshServers() } else failed = true
                    },
                    enabled = pass.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (failed) Text("Wrong passphrase", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
            }
            return@ScreenFrame
        }

        val servers by vm.servers.collectAsStateWithLifecycle()
        val users by vm.users.collectAsStateWithLifecycle()
        val selected by vm.selected.collectAsStateWithLifecycle()
        val busy by vm.busy.collectAsStateWithLifecycle()
        val message by vm.message.collectAsStateWithLifecycle()

        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            message?.let { m -> item { Text(m, color = Moss, style = MaterialTheme.typography.labelSmall) } }
            if (servers.isEmpty()) {
                item {
                    Text(
                        "No saved servers. Provision one from Deploy while the vault is unlocked, and it'll appear here.",
                        style = MaterialTheme.typography.labelSmall,
                        color = Dim,
                    )
                }
            }
            items(servers, key = { it.id }) { s ->
                val open = s.id == selected
                PanelCard(onClick = { vm.select(s.id) }) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(LeshiyIcons.Server, null, tint = if (open) Wisp else Moss, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(s.label, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(s.host, style = MaterialTheme.typography.labelSmall, color = Dim)
                        }
                        Icon(if (open) LeshiyIcons.ChevronDown else LeshiyIcons.ChevronRight, null, tint = Moss, modifier = Modifier.size(18.dp))
                    }

                    if (open) {
                        Spacer(Modifier.size(12.dp))
                        SectionLabel("Users")
                        users.forEach { u ->
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                                Column(Modifier.weight(1f)) {
                                    Text(u.label ?: "(orphan)", style = MaterialTheme.typography.bodyMedium, color = if (u.enabled) MaterialTheme.colorScheme.onBackground else MaterialTheme.colorScheme.error)
                                    Text(u.shortId, style = MaterialTheme.typography.labelSmall, color = Dim)
                                }
                                IconBtn(LeshiyIcons.Trash, "Revoke", tint = MaterialTheme.colorScheme.error) { vm.deleteUser(s.id, u.shortId) }
                            }
                        }
                        Spacer(Modifier.size(8.dp))
                        var label by remember(s.id) { mutableStateOf("") }
                        Field(
                            label, { label = it }, "New user label",
                            trailing = { IconBtn(LeshiyIcons.Plus, "Add user", tint = Wisp) { vm.addUser(s.id, label) { uri -> onUserUri(uri, label.ifBlank { "phone" }); label = "" } } },
                        )
                        Spacer(Modifier.size(10.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            SmallAction("Check status", enabled = !busy) { vm.status(s.id) }
                            SmallAction("Teardown", enabled = !busy, danger = true) { vm.teardown(s.id, false) }
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
