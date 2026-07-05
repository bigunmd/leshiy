package dev.leshiy

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.ui.theme.LeshiyTheme

/**
 * Phase 1 spike screen: a URI field, Connect/Disconnect, and a live status line. Proves the
 * Compose UI -> VpnService -> Rust bridge path end to end. Full UI lands in Phase 2.
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
                    SpikeScreen(onConnect = ::connect, onDisconnect = ::disconnect)
                }
            }
        }
    }

    private fun connect(uri: String) {
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
private fun SpikeScreen(onConnect: (String) -> Unit, onDisconnect: () -> Unit) {
    var uri by remember { mutableStateOf("") }
    val running by AppState.running.collectAsStateWithLifecycle()
    val status by AppState.status.collectAsStateWithLifecycle()

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Leshiy", style = androidx.compose.material3.MaterialTheme.typography.displaySmall)
        OutlinedTextField(
            value = uri,
            onValueChange = { uri = it },
            label = { Text("leshiy:// URI") },
            modifier = Modifier.fillMaxWidth(),
        )
        if (running) {
            OutlinedButton(onClick = onDisconnect) { Text("Disconnect") }
        } else {
            Button(onClick = { onConnect(uri.trim()) }) { Text("Connect") }
        }
        val s = status
        Text(
            text = if (s == null) "idle" else "${s.state}  ↑${s.upBytes}B  ↓${s.downBytes}B",
            style = androidx.compose.material3.MaterialTheme.typography.labelSmall,
        )
    }
}
