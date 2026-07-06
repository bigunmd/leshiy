package dev.leshiy.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.leshiy.ui.components.NavRow
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Warn
import dev.leshiy.ui.theme.Wisp

@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onServers: () -> Unit,
    onSplit: () -> Unit,
    onDeploy: () -> Unit,
    onManage: () -> Unit,
) {
    ScreenFrame("Settings", onBack = onBack) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            SectionLabel("Connection")
            NavRow(LeshiyIcons.Server, "Servers", "Import, choose and manage server profiles", tint = Wisp, onClick = onServers)
            NavRow(LeshiyIcons.Shield, "Split tunnel", "Route only chosen apps through the VPN", tint = Wisp, onClick = onSplit)

            Spacer(Modifier.size(6.dp))
            SectionLabel("Your servers")
            NavRow(LeshiyIcons.Rocket, "Deploy a server", "Provision a fresh VPS over SSH", tint = Wisp, onClick = onDeploy)
            NavRow(LeshiyIcons.Gear, "Manage servers", "Users, status and teardown", tint = Warn, onClick = onManage)
        }
    }
}
