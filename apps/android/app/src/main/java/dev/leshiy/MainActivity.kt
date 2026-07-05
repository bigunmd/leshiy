package dev.leshiy

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
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
import dev.leshiy.ui.QrScanActivity
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.LeshiyTheme
import dev.leshiy.ui.theme.Warn
import dev.leshiy.ui.theme.Wisp
import uniffi.leshiy_mobile.ConnState

/**
 * Phase 2 Connect MVP: a ViewModel-driven Deep Bog screen — URI field with QR import, a
 * state-colored Connect button, and live counters. The tunnel itself runs in [LeshiyVpnService].
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
                    val vm: ConnectViewModel = viewModel()
                    val ui by vm.uiState.collectAsStateWithLifecycle()

                    val qrLauncher = rememberQrLauncher { uri -> vm.onUriChange(uri) }

                    ConnectScreen(
                        ui = ui,
                        onUriChange = vm::onUriChange,
                        onScan = { qrLauncher.launch(Intent(this, QrScanActivity::class.java)) },
                        onConnect = {
                            vm.persist(vm.currentUri())
                            connect(vm.currentUri())
                        },
                        onDisconnect = ::disconnect,
                    )
                }
            }
        }
    }

    private fun connect(uri: String) {
        if (uri.isEmpty()) return
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

@Composable
private fun rememberQrLauncher(onUri: (String) -> Unit) =
    androidx.activity.compose.rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            result.data?.getStringExtra(QrScanActivity.EXTRA_URI)?.let(onUri)
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
    onUriChange: (String) -> Unit,
    onScan: () -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Leshiy", style = MaterialTheme.typography.displaySmall)

        OutlinedTextField(
            value = ui.uri,
            onValueChange = onUriChange,
            label = { Text("leshiy:// URI") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            trailingIcon = {
                TextButton(onClick = onScan) { Text("QR") }
            },
        )

        // State-colored status disc.
        Box(
            modifier = Modifier
                .size(140.dp)
                .clip(CircleShape),
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
                enabled = ui.uri.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Wisp),
            ) { Text("Connect") }
        }

        Text(
            text = "↑ ${ui.upBytes} B   ↓ ${ui.downBytes} B",
            style = MaterialTheme.typography.labelSmall,
            color = Dim,
        )
    }
}
