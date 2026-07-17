package dev.leshiy.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.ui.components.ConnectOrb
import dev.leshiy.ui.components.IconBtn
import dev.leshiy.ui.components.UpdateCard
import dev.leshiy.ui.formatBytes
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.ChipText
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.PlexMono
import dev.leshiy.ui.theme.Warn
import dev.leshiy.ui.theme.Wisp
import dev.leshiy.ui.theme.WispBright
import dev.leshiy.ui.ConnectViewModel
import dev.leshiy.ui.ProfilesViewModel
import uniffi.leshiy_mobile.ConnState

@Composable
fun ConnectScreen(
    connectVm: ConnectViewModel,
    profilesVm: ProfilesViewModel,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
    onOpenSettings: () -> Unit,
    onOpenServers: () -> Unit,
) {
    val ui by connectVm.uiState.collectAsStateWithLifecycle()
    val profiles by profilesVm.profiles.collectAsStateWithLifecycle()
    val active = profiles.firstOrNull { it.isActive }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.safeDrawing),
    ) {
        // Top bar: wordmark + settings cog.
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(LeshiyIcons.Wisp, null, tint = Wisp, modifier = Modifier.size(16.dp))
            Spacer(Modifier.width(8.dp))
            Text(
                "LESHIY",
                fontWeight = FontWeight.Bold,
                letterSpacing = 2.sp,
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onBackground,
            )
            Spacer(Modifier.weight(1f))
            IconBtn(LeshiyIcons.Gear, "Settings", tint = Dim, onClick = onOpenSettings)
        }

        UpdateCard(Modifier.padding(horizontal = 18.dp))

        // Hero: orb + status + active-server chip.
        Column(
            modifier = Modifier.fillMaxSize().weight(1f).padding(bottom = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            ConnectOrb(
                state = ui.state,
                enabled = active != null || ui.running,
                onToggle = {
                    if (ui.running) onDisconnect() else active?.let { onConnect(it.uri) }
                },
            )

            Spacer(Modifier.size(28.dp))
            StatusReadout(ui.state, ui.upBytes, ui.downBytes, ui.rttMs)

            Spacer(Modifier.size(10.dp))
            if (active == null) {
                Text(
                    LocalStrings.current.noServerSelected,
                    fontFamily = PlexMono,
                    fontSize = 10.sp,
                    letterSpacing = 2.sp,
                    color = Dim.copy(alpha = 0.7f),
                )
            }

            Spacer(Modifier.size(28.dp))
            ServerChip(name = active?.name, onClick = onOpenServers)
        }
    }
}

@Composable
private fun StatusReadout(state: ConnState, up: ULong, down: ULong, rttMs: UInt) {
    val s = LocalStrings.current
    val label = when (state) {
        ConnState.CONNECTED -> s.stProtected
        ConnState.CONNECTING -> s.stConnecting
        ConnState.RECONNECTING -> s.stReconnecting
        ConnState.FAILED -> s.stError
        ConnState.DISCONNECTED -> s.stDisconnected
    }
    val color = when (state) {
        ConnState.CONNECTED, ConnState.CONNECTING, ConnState.RECONNECTING -> WispBright
        ConnState.FAILED -> Warn
        ConnState.DISCONNECTED -> Dim
    }
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            if (state == ConnState.CONNECTED) Text("●", color = WispBright, fontSize = 10.sp)
            Text(label, fontFamily = PlexMono, fontSize = 13.sp, letterSpacing = 1.sp, fontWeight = FontWeight.Medium, color = color)
        }
        if (state == ConnState.CONNECTED) {
            Row(horizontalArrangement = Arrangement.spacedBy(18.dp)) {
                Meter(LeshiyIcons.ArrowDown, formatBytes(down))
                Meter(LeshiyIcons.ArrowUp, formatBytes(up))
                if (rttMs > 0u) Meter(LeshiyIcons.Bolt, "$rttMs ms")
            }
        }
    }
}

@Composable
private fun Meter(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        Icon(icon, null, tint = Dim, modifier = Modifier.size(10.dp))
        Text(text, fontFamily = PlexMono, fontSize = 12.sp, color = Dim)
    }
}

@Composable
private fun ServerChip(name: String?, onClick: () -> Unit) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
        androidx.compose.material3.Surface(
            onClick = onClick,
            shape = androidx.compose.foundation.shape.RoundedCornerShape(50),
            color = MaterialTheme.colorScheme.surface,
            border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 9.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Icon(LeshiyIcons.Wisp, null, tint = Wisp, modifier = Modifier.size(14.dp))
                Text(
                    name ?: LocalStrings.current.chooseServer,
                    fontSize = 13.sp,
                    color = if (name != null) ChipText else Dim,
                )
                Icon(LeshiyIcons.ChevronDown, null, tint = Moss, modifier = Modifier.size(14.dp))
            }
        }
        Text(
            LocalStrings.current.manageServersLink,
            fontFamily = PlexMono,
            fontSize = 10.sp,
            letterSpacing = 2.sp,
            color = Moss,
            textAlign = TextAlign.Center,
        )
    }
}
