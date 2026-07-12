package dev.leshiy.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.ui.ManageViewModel
import dev.leshiy.ui.ServerStatus
import dev.leshiy.ui.components.Field
import dev.leshiy.ui.components.LoadingButton
import dev.leshiy.ui.components.NavRow
import dev.leshiy.ui.components.OutlineButton
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.components.StatusPill
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Warn
import dev.leshiy.ui.theme.Wisp

/** One server's management hub: sudo gate, run-status, a way into its users, and teardown. */
@Composable
fun ServerDetailScreen(
    vm: ManageViewModel,
    onOpenUsers: () -> Unit,
    onBack: () -> Unit,
) {
    val s = LocalStrings.current
    val selected by vm.selected.collectAsStateWithLifecycle()
    val servers by vm.servers.collectAsStateWithLifecycle()
    val status by vm.status.collectAsStateWithLifecycle()
    val pending by vm.pending.collectAsStateWithLifecycle()
    val message by vm.message.collectAsStateWithLifecycle()
    val sudoPw by vm.sudo.collectAsStateWithLifecycle()

    val server = servers.firstOrNull { it.id == selected }
    if (server == null) {
        ScreenFrame(s.manage, onBack = onBack) {}
        return
    }

    ScreenFrame(server.label, onBack = onBack) {
        Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("${server.host}:${server.port}", style = MaterialTheme.typography.labelMedium, color = Dim)

            val needsSudo = server.sudo && sudoPw[server.id].isNullOrBlank()
            if (needsSudo) {
                SectionLabel(s.sudoPasswordManage)
                Text(s.sudoRequiredNote, style = MaterialTheme.typography.labelSmall, color = Dim)
                var pw by remember(server.id) { mutableStateOf("") }
                Field(pw, { pw = it }, s.sudoPasswordManage)
                LoadingButton(
                    s.sudoApply,
                    onClick = { vm.submitSudo(server.id, pw) },
                    enabled = pw.isNotBlank(),
                    modifier = Modifier.fillMaxWidth(),
                )
                return@Column
            }

            // Run status.
            SectionLabel(s.serverStatus)
            val checking = pending == "status"
            val (label, dot) = when {
                checking -> s.statusChecking to Wisp
                status == ServerStatus.RUNNING -> s.statusRunningLabel to Wisp
                status == ServerStatus.STOPPED -> s.statusStoppedLabel to Warn
                status == ServerStatus.ERROR -> s.statusErrorLabel to MaterialTheme.colorScheme.error
                else -> s.statusUnknown to Dim
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusPill(label, dot, loading = checking)
                Spacer(Modifier.width(12.dp))
                OutlineButton(
                    s.checkStatus,
                    onClick = { vm.checkStatus(server.id) },
                    loading = checking,
                    modifier = Modifier.weight(1f),
                )
            }
            // Any op failure (status check, teardown) surfaces here.
            message?.let { Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error) }

            SectionLabel(s.users)
            NavRow(icon = LeshiyIcons.Users, title = s.users, subtitle = s.manageUsersSubtitle, onClick = onOpenUsers)

            Spacer(Modifier.size(2.dp))
            OutlineButton(
                s.teardown,
                onClick = { vm.teardown(server.id, false) { onBack() } },
                loading = pending == "teardown",
                danger = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}
