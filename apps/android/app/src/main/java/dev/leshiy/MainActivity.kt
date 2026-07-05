package dev.leshiy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import dev.leshiy.ui.ConnectUiState
import dev.leshiy.ui.ConnectViewModel
import dev.leshiy.ui.ProfilesViewModel
import dev.leshiy.ui.QrScanActivity
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.LeshiyTheme
import dev.leshiy.ui.theme.Warn
import dev.leshiy.ui.theme.Wisp
import uniffi.leshiy_mobile.ConnState
import uniffi.leshiy_mobile.ProfileInfo

private enum class Screen { Connect, Profiles }

/**
 * Phase 3: multiple servers + always-on. Two screens — Connect (drives the active profile) and
 * Profiles (add/select/delete). The active profile URI is also what always-on/boot connects.
 */
class MainActivity : ComponentActivity() {

    private var pendingUri: String? = null

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) pendingUri?.let(::startTunnel)
            pendingUri = null
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            LeshiyTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val connectVm: ConnectViewModel = viewModel()
                    val profilesVm: ProfilesViewModel = viewModel()
                    val ui by connectVm.uiState.collectAsStateWithLifecycle()
                    val profiles by profilesVm.profiles.collectAsStateWithLifecycle()
                    var screen by remember { mutableStateOf(Screen.Connect) }

                    val qrLauncher = rememberLauncherForActivityResult(
                        ActivityResultContracts.StartActivityForResult(),
                    ) { result ->
                        if (result.resultCode == Activity.RESULT_OK) {
                            result.data?.getStringExtra(QrScanActivity.EXTRA_URI)
                                ?.let { scannedUri.value = it }
                        }
                    }

                    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            TextButton(onClick = { screen = Screen.Connect }) { Text("Connect") }
                            TextButton(onClick = { screen = Screen.Profiles }) { Text("Profiles") }
                        }
                        when (screen) {
                            Screen.Connect -> ConnectScreen(
                                ui = ui,
                                activeName = profiles.firstOrNull { it.isActive }?.name,
                                onConnect = { connect(profilesVm.activeUri()) },
                                onDisconnect = ::disconnect,
                            )
                            Screen.Profiles -> ProfilesScreen(
                                profiles = profiles,
                                scannedUri = scannedUri,
                                onScan = {
                                    qrLauncher.launch(Intent(this@MainActivity, QrScanActivity::class.java))
                                },
                                onAdd = { uri, name -> profilesVm.add(uri, name) },
                                onActivate = profilesVm::activate,
                                onRemove = profilesVm::remove,
                            )
                        }
                    }
                }
            }
        }
    }

    // Holds a URI captured by the QR scanner until the Add form consumes it.
    private val scannedUri = androidx.compose.runtime.mutableStateOf("")

    private fun connect(uri: String?) {
        if (uri.isNullOrEmpty()) return
        val consent = VpnService.prepare(this)
        if (consent != null) {
            pendingUri = uri
            vpnConsent.launch(consent)
        } else {
            startTunnel(uri)
        }
    }

    private fun startTunnel(uri: String) {
        startService(
            Intent(this, LeshiyVpnService::class.java).putExtra(LeshiyVpnService.EXTRA_URI, uri),
        )
    }

    private fun disconnect() {
        startService(
            Intent(this, LeshiyVpnService::class.java).setAction(LeshiyVpnService.ACTION_STOP),
        )
    }
}

private fun stateColor(s: ConnState): Color = when (s) {
    ConnState.CONNECTED -> Wisp
    ConnState.FAILED -> Warn
    else -> Dim
}

@Composable
private fun ConnectScreen(
    ui: ConnectUiState,
    activeName: String?,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(top = 24.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(activeName ?: "No server selected", style = MaterialTheme.typography.titleLarge)

        Box(
            modifier = Modifier.size(140.dp).clip(CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = ui.state.name.lowercase(),
                color = stateColor(ui.state),
                style = MaterialTheme.typography.titleLarge,
                textAlign = TextAlign.Center,
            )
        }

        if (ui.running) {
            OutlinedButton(onClick = onDisconnect, modifier = Modifier.fillMaxWidth()) {
                Text("Disconnect")
            }
        } else {
            Button(
                onClick = onConnect,
                enabled = activeName != null,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Wisp),
            ) { Text(if (activeName == null) "Select a server first" else "Connect") }
        }

        Text(
            text = "↑ ${ui.upBytes} B   ↓ ${ui.downBytes} B",
            style = MaterialTheme.typography.labelSmall,
            color = Dim,
        )
    }
}

@Composable
private fun ProfilesScreen(
    profiles: List<ProfileInfo>,
    scannedUri: androidx.compose.runtime.MutableState<String>,
    onScan: () -> Unit,
    onAdd: (String, String) -> Boolean,
    onActivate: (String) -> Unit,
    onRemove: (String) -> Unit,
) {
    var name by remember { mutableStateOf("") }

    Column(
        modifier = Modifier.fillMaxSize().padding(top = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxWidth().weight(1f),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(profiles, key = { it.id }) { p ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    TextButton(onClick = { onActivate(p.id) }) {
                        Text(
                            text = (if (p.isActive) "● " else "○ ") + p.name,
                            color = if (p.isActive) Wisp else Dim,
                        )
                    }
                    Box(modifier = Modifier.weight(1f))
                    TextButton(onClick = { onRemove(p.id) }) { Text("✕", color = Warn) }
                }
            }
        }

        // Add form: name + URI (paste or QR).
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text("Name") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = scannedUri.value,
            onValueChange = { scannedUri.value = it },
            label = { Text("leshiy:// URI") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            trailingIcon = { TextButton(onClick = onScan) { Text("QR") } },
        )
        Button(
            onClick = {
                if (onAdd(scannedUri.value, name)) {
                    scannedUri.value = ""
                    name = ""
                }
            },
            enabled = scannedUri.value.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Wisp),
        ) { Text("Add server") }
    }
}
