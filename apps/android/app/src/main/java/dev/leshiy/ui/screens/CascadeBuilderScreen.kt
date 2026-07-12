package dev.leshiy.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
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
import dev.leshiy.ui.CascadeViewModel
import dev.leshiy.ui.HopRole
import dev.leshiy.ui.ManageViewModel
import dev.leshiy.ui.Slot
import dev.leshiy.ui.SlotSource
import dev.leshiy.ui.components.Field
import dev.leshiy.ui.components.IconBtn
import dev.leshiy.ui.components.LoadingButton
import dev.leshiy.ui.components.OutlineButton
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.components.RoleBadge
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.Wisp
import uniffi.leshiy_mobile.ServerInfo

/** Guided assembly of a multi-hop cascade: fill each slot, then deploy exit-first. */
@Composable
fun CascadeBuilderScreen(
    vm: CascadeViewModel,
    manageVm: ManageViewModel,
    onStartBuild: () -> Unit,
    onBack: () -> Unit,
) {
    val s = LocalStrings.current
    val context = LocalContext.current
    var unlocked by remember { mutableStateOf(VaultHolder.unlocked) }
    androidx.compose.runtime.LaunchedEffect(unlocked) { if (unlocked) manageVm.refreshServers() }

    ScreenFrame(s.buildCascade, onBack = onBack) {
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
                if (failed) Text(s.wrongPassphrase, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
            }
            return@ScreenFrame
        }

        val plan by vm.plan.collectAsStateWithLifecycle()
        val servers by manageVm.servers.collectAsStateWithLifecycle()
        var chooserFor by remember { mutableStateOf<Int?>(null) }

        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(s.cascadeIntro, style = MaterialTheme.typography.labelSmall, color = Dim)

            CascadeDiagram(plan.slots)

            plan.slots.forEachIndexed { i, slot ->
                SlotCard(
                    slot = slot,
                    summary = slotSummary(slot, servers, s),
                    onClick = { chooserFor = i },
                    onRemove = if (slot.role == HopRole.MIDDLE) ({ vm.removeMiddle(i) }) else null,
                )
            }

            OutlineButton(s.addMiddleHop, onClick = { vm.addMiddle() }, modifier = Modifier.fillMaxWidth())

            LoadingButton(
                s.startBuilding,
                onClick = onStartBuild,
                enabled = plan.isReady,
                modifier = Modifier.fillMaxWidth(),
            )
        }

        chooserFor?.let { i ->
            val slot = plan.slots[i]
            SlotChooserSheet(
                slot = slot,
                candidates = servers.filter { it.role == slot.role.wireRole() },
                onPick = { src -> vm.setSource(i, src); chooserFor = null },
                onDismiss = { chooserFor = null },
            )
        }
    }
}

private fun HopRole.wireRole(): String = when (this) {
    HopRole.ENTRY -> "entry"; HopRole.MIDDLE -> "middle"; HopRole.EXIT -> "exit"
}

@Composable
private fun CascadeDiagram(slots: List<Slot>) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text("📱", style = MaterialTheme.typography.titleMedium)
        slots.forEach { slot ->
            Text(" ▸ ", color = Moss)
            RoleBadge(role = slot.role.wireRole())
            if (slot.source == null) Text("·", color = Dim)
        }
        Text(" ▸ ", color = Moss)
        Text("🌐", style = MaterialTheme.typography.titleMedium)
    }
}

@Composable
private fun SlotCard(slot: Slot, summary: String, onClick: () -> Unit, onRemove: (() -> Unit)?) {
    val s = LocalStrings.current
    val title = when (slot.role) {
        HopRole.ENTRY -> s.slotEntry
        HopRole.MIDDLE -> s.slotMiddle
        HopRole.EXIT -> s.slotExit
    }
    PanelCard(onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground)
                Text(summary, style = MaterialTheme.typography.labelSmall, color = if (slot.source == null) Dim else Wisp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            if (onRemove != null) {
                IconBtn(LeshiyIcons.Trash, s.remove, tint = MaterialTheme.colorScheme.error, onClick = onRemove)
            }
            Icon(LeshiyIcons.ChevronRight, null, tint = Moss, modifier = Modifier.size(18.dp))
        }
    }
}

@Composable
private fun slotSummary(slot: Slot, servers: List<ServerInfo>, s: dev.leshiy.ui.i18n.Strings): String =
    when (val src = slot.source) {
        null -> s.setSlot
        SlotSource.DeployNew -> s.sourceDeployNew
        is SlotSource.UseExisting -> servers.firstOrNull { it.id == src.serverId }?.label ?: src.serverId
        is SlotSource.PasteLink -> s.sourcePasteLink
    }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SlotChooserSheet(
    slot: Slot,
    candidates: List<ServerInfo>,
    onPick: (SlotSource) -> Unit,
    onDismiss: () -> Unit,
) {
    val s = LocalStrings.current
    val sheet = rememberModalBottomSheetState()
    var pasting by remember { mutableStateOf(false) }
    var link by remember { mutableStateOf("") }
    var picking by remember { mutableStateOf(false) }

    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = sheet) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            SectionLabel(
                when (slot.role) {
                    HopRole.ENTRY -> s.slotEntry
                    HopRole.MIDDLE -> s.slotMiddle
                    HopRole.EXIT -> s.slotExit
                },
            )
            ChooserRow(s.sourceDeployNew) { onPick(SlotSource.DeployNew) }
            ChooserRow(s.sourceUseMine) { picking = !picking; pasting = false }
            if (picking) {
                if (candidates.isEmpty()) {
                    Text(s.noCandidates, style = MaterialTheme.typography.labelSmall, color = Dim, modifier = Modifier.padding(start = 8.dp))
                }
                candidates.forEach { srv ->
                    PanelCard(onClick = { onPick(SlotSource.UseExisting(srv.id)) }) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(LeshiyIcons.Server, null, tint = Moss, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(10.dp))
                            Text(srv.label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onBackground)
                        }
                    }
                }
            }
            // Entry must be the user's own node — no external paste.
            if (slot.role != HopRole.ENTRY) {
                ChooserRow(s.sourcePasteLink) { pasting = !pasting; picking = false }
                if (pasting) {
                    Field(link, { link = it }, s.pasteConnectorLink)
                    PrimaryButton(
                        s.doneAction,
                        onClick = { onPick(SlotSource.PasteLink(link.trim())) },
                        enabled = link.isNotBlank(),
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            }
            Spacer(Modifier.size(8.dp))
        }
    }
}

@Composable
private fun ChooserRow(text: String, onClick: () -> Unit) {
    PanelCard(onClick = onClick) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(text, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground, modifier = Modifier.weight(1f))
            Icon(LeshiyIcons.ChevronRight, null, tint = Moss, modifier = Modifier.size(18.dp))
        }
    }
}
