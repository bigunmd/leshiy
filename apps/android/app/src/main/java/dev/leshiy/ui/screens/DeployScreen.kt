package dev.leshiy.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.ui.ProvisionViewModel
import dev.leshiy.ui.components.Field
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.PlexMono
import dev.leshiy.ui.theme.Warn

@Composable
fun DeployScreen(
    vm: ProvisionViewModel,
    onProvisioned: (String, String) -> Unit,
    onBack: () -> Unit,
) {
    val state by vm.state.collectAsStateWithLifecycle()
    var host by remember { mutableStateOf("") }
    var user by remember { mutableStateOf("root") }
    var password by remember { mutableStateOf("") }
    var dest by remember { mutableStateOf("www.microsoft.com:443") }
    var port by remember { mutableStateOf("443") }

    ScreenFrame("Deploy a server", onBack = onBack) {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "Provision a fresh VPS into a leshiy server over SSH. You'll need root (or sudo) access.",
                style = MaterialTheme.typography.labelSmall,
                color = Dim,
            )
            SectionLabel("Target")
            Field(host, { host = it }, "VPS host or IP")
            Field(user, { user = it }, "SSH user")
            Field(password, { password = it }, "SSH password")

            SectionLabel("Camouflage")
            Field(dest, { dest = it }, "Borrowed TLS site (host:port)")
            Field(port, { port = it }, "REALITY port")

            PrimaryButton(
                text = if (state.running) "Provisioning…" else "Provision server",
                onClick = {
                    vm.provision(host, user, password, dest, port.toIntOrNull() ?: 443) { uri ->
                        onProvisioned(uri, host.trim())
                    }
                },
                enabled = !state.running && host.isNotBlank() && password.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            )

            state.error?.let {
                Text(it, color = Warn, style = MaterialTheme.typography.labelSmall)
            }

            if (state.log.isNotEmpty()) {
                SectionLabel("Progress")
                PanelCard {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        state.log.forEach { line ->
                            Text(
                                line,
                                fontFamily = PlexMono,
                                style = MaterialTheme.typography.labelSmall,
                                color = Dim,
                            )
                        }
                    }
                }
            }
        }
    }
}
