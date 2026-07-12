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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.ui.ManageViewModel
import dev.leshiy.ui.components.Field
import dev.leshiy.ui.components.IconBtn
import dev.leshiy.ui.components.LoadingButton
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.components.Spinner
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.Wisp

/** The users on one server — issue a new credential (→ QR) or revoke an existing one. */
@Composable
fun ServerUsersScreen(
    vm: ManageViewModel,
    onOpenCredential: () -> Unit,
    onBack: () -> Unit,
) {
    val s = LocalStrings.current
    val selected by vm.selected.collectAsStateWithLifecycle()
    val servers by vm.servers.collectAsStateWithLifecycle()
    val users by vm.users.collectAsStateWithLifecycle()
    val pending by vm.pending.collectAsStateWithLifecycle()
    val message by vm.message.collectAsStateWithLifecycle()

    val server = servers.firstOrNull { it.id == selected }
    if (server == null) {
        ScreenFrame(s.users, onBack = onBack) {}
        return
    }

    // Load the roster on entry (needs the sudo password, already supplied on the detail screen).
    androidx.compose.runtime.LaunchedEffect(server.id) { vm.loadUsers(server.id) }

    var label by remember { mutableStateOf("") }

    ScreenFrame(s.users, onBack = onBack) {
        LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            item { SectionLabel("${s.users} · ${server.label}") }

            message?.let { m -> item { Text(m, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall) } }

            if (pending == "loadUsers" && users.isEmpty()) {
                item { Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { Spinner() } }
            }
            items(users, key = { it.shortId }) { u ->
                val hasUri = u.uri.isNotBlank()
                PanelCard(onClick = if (hasUri) {
                    { vm.presentCredential(u.label ?: u.shortId, u.uri); onOpenCredential() }
                } else null) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                u.label ?: s.orphan,
                                style = MaterialTheme.typography.bodyLarge,
                                color = if (u.enabled) MaterialTheme.colorScheme.onBackground else MaterialTheme.colorScheme.error,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Text(u.shortId, style = MaterialTheme.typography.labelSmall, color = Dim)
                        }
                        if (hasUri) {
                            Icon(LeshiyIcons.Qr, s.showQr, tint = Moss, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                        }
                        if (pending == "delete:${u.shortId}") {
                            Spinner(size = 20, color = MaterialTheme.colorScheme.error)
                            Spacer(Modifier.width(8.dp))
                        } else {
                            IconBtn(LeshiyIcons.Trash, s.remove, tint = MaterialTheme.colorScheme.error) { vm.deleteUser(server.id, u.shortId) }
                        }
                    }
                }
            }

            item { Spacer(Modifier.size(6.dp)); SectionLabel(s.addUser) }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Field(label, { label = it }, s.newUserLabel)
                    LoadingButton(
                        s.addUser,
                        onClick = {
                            vm.addUser(server.id, label) { cred ->
                                vm.presentCredential(cred.label, cred.uri)
                                label = ""
                                onOpenCredential()
                            }
                        },
                        loading = pending == "addUser",
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
        }
    }
}
