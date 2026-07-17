package dev.leshiy.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.ui.theme.Bg0
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import dev.leshiy.ui.ProvisionViewModel
import dev.leshiy.ui.components.Field
import dev.leshiy.ui.components.HelpField
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.PlexMono
import dev.leshiy.ui.theme.Warn
import dev.leshiy.ui.theme.Wisp
import uniffi.leshiy_mobile.ProvisionConfig
import uniffi.leshiy_mobile.keyNeedsPassphrase

/** Preset injected by the Cascade Builder: fixes this deploy's role + downstream wiring. */
data class ProvisionPreset(
    val role: String,          // "entry" | "middle" | "exit"
    val connector: String?,    // downstream connector uri (entry/middle)
    val downstreamId: String?, // downstream server id (local ref)
    val labelHint: String,     // default label, e.g. "riga-entry"
    val nextHopName: String?,  // for the banner, e.g. "Oslo"
)

@Composable
fun DeployScreen(
    vm: ProvisionViewModel,
    onStarted: () -> Unit,
    onBack: () -> Unit,
    preset: ProvisionPreset? = null,
) {
    val s = LocalStrings.current
    val state by vm.state.collectAsStateWithLifecycle()
    var vaultPass by remember { mutableStateOf("") }

    // Required.
    var host by remember { mutableStateOf("") }
    var user by remember { mutableStateOf("root") }
    var password by remember { mutableStateOf("") }
    var dest by remember { mutableStateOf("www.microsoft.com:443") }
    var port by remember { mutableStateOf("443") }
    // SSH auth: password or private key.
    var useKey by remember { mutableStateOf(false) }
    var pem by remember { mutableStateOf("") }
    var keyPass by remember { mutableStateOf("") }
    val context = LocalContext.current
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val keyFileLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)!!.bufferedReader().readText()
                }
            }.getOrNull()?.let { pem = it }
        }
    }
    // Advanced / optional.
    var showAdvanced by remember { mutableStateOf(false) }
    var sshPort by remember { mutableStateOf("22") }
    var sudoPass by remember { mutableStateOf("") }
    var label by remember { mutableStateOf("") }
    var quicPort by remember { mutableStateOf("") }
    var image by remember { mutableStateOf("") }
    var userLabel by remember { mutableStateOf("") }
    var dns by remember { mutableStateOf("") }

    ScreenFrame(s.deploy, onBack = onBack) {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            if (preset != null) {
                PanelCard {
                    Text(
                        s.cascadeDeployBanner.format(s.roleName(preset.role), preset.nextHopName ?: s.internet),
                        style = MaterialTheme.typography.labelMedium,
                        color = Wisp,
                    )
                }
            } else {
                Text(s.deployIntro, style = MaterialTheme.typography.labelSmall, color = Dim)
            }

            SectionLabel(s.target)
            HelpField(host, { host = it }, s.vpsHost, s.helpHost)
            HelpField(user, { user = it }, s.sshUser, s.helpSshUser)

            // Auth method: password or SSH key.
            Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surface, border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)) {
                Row(Modifier.padding(3.dp), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                    AuthSeg(s.authPassword, !useKey, Modifier.weight(1f)) { useKey = false }
                    AuthSeg(s.authKey, useKey, Modifier.weight(1f)) { useKey = true }
                }
            }
            if (useKey) {
                HelpField(pem, { pem = it }, s.sshPrivateKey, s.helpKey, singleLine = false)
                androidx.compose.material3.OutlinedButton(
                    onClick = { keyFileLauncher.launch(arrayOf("*/*")) },
                    shape = RoundedCornerShape(12.dp),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(LeshiyIcons.File, null, tint = Wisp, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(s.loadKeyFile, color = Wisp, style = MaterialTheme.typography.labelLarge)
                }
                // Detect an encrypted key so we can point the user at the passphrase field.
                val keyEncrypted = remember(pem) {
                    pem.isNotBlank() && runCatching { keyNeedsPassphrase(pem) }.getOrDefault(false)
                }
                HelpField(keyPass, { keyPass = it }, s.keyPassphraseOpt, s.helpKeyPassphrase)
                if (keyEncrypted && keyPass.isBlank()) {
                    Text(s.keyEncryptedHint, style = MaterialTheme.typography.labelSmall, color = Warn, modifier = Modifier.padding(start = 4.dp))
                }
            } else {
                HelpField(password, { password = it }, s.sshPassword, s.helpSshPassword)
            }

            SectionLabel(s.camouflage)
            HelpField(dest, { dest = it }, s.borrowedSite, s.helpDest)
            HelpField(port, { port = it }, s.realityPort, s.helpListenPort)

            // Advanced (optional) section.
            Row(
                modifier = Modifier.fillMaxWidth().clickable { showAdvanced = !showAdvanced }.padding(vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(if (showAdvanced) LeshiyIcons.ChevronDown else LeshiyIcons.ChevronRight, null, tint = Moss, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                SectionLabel(s.advanced)
            }
            if (showAdvanced) {
                HelpField(sshPort, { sshPort = it }, s.sshPort, s.helpSshPort)
                HelpField(sudoPass, { sudoPass = it }, s.sudoPasswordOpt, s.helpSudo)
                HelpField(label, { label = it }, s.serverLabelOpt, s.helpLabel)
                HelpField(quicPort, { quicPort = it }, s.quicPortOpt, s.helpQuic)
                HelpField(image, { image = it }, s.containerImageOpt, s.helpImage)
                HelpField(userLabel, { userLabel = it }, s.firstUserLabelOpt, s.helpUserLabel)
                HelpField(dns, { dns = it }, s.dnsOverrideOpt, s.helpDns)
            }

            // Save-for-management (vault) setup. The Cascade Builder owns the vault, so hide
            // this when arriving with a preset (the vault is already unlocked there).
            if (preset == null) {
                SectionLabel(s.saveForManagement)
                if (dev.leshiy.data.VaultHolder.unlocked) {
                    Text(s.vaultUnlockedNote, style = MaterialTheme.typography.labelSmall, color = Dim)
                } else {
                    HelpField(vaultPass, { vaultPass = it }, s.vaultPassphraseOptDeploy, s.helpVaultDeploy)
                }
            }

            Spacer(Modifier.size(2.dp))
            PrimaryButton(
                text = if (state.running) s.provisioning else s.provision,
                onClick = {
                    // If a vault passphrase was given, unlock first so the server is saved for management.
                    if (!dev.leshiy.data.VaultHolder.unlocked && vaultPass.isNotBlank()) {
                        dev.leshiy.data.VaultHolder.unlock(context, vaultPass)
                    }
                    val cfg = ProvisionConfig(
                        host = host.trim(),
                        sshPort = sshPort.trim().toUShortOrNull() ?: 22u,
                        sshUser = user.trim().ifBlank { "root" },
                        sshPassword = if (useKey) null else password.ifBlank { null },
                        sshPrivateKey = if (useKey) pem.ifBlank { null } else null,
                        sshKeyPassphrase = if (useKey) keyPass.ifBlank { null } else null,
                        dest = dest.trim(),
                        listenPort = (port.trim().toIntOrNull() ?: 443).toUShort(),
                        label = label.trim().ifBlank { null },
                        sudoPassword = sudoPass.ifBlank { null },
                        quicPort = quicPort.trim().toUShortOrNull(),
                        imageRef = image.trim().ifBlank { null },
                        userLabel = userLabel.trim().ifBlank { null },
                        dnsOverride = dns.trim().ifBlank { null },
                        role = preset?.role ?: "single",
                        downstream = preset?.downstreamId,
                        connector = preset?.connector,
                    )
                    val serverName = label.trim().ifBlank { host.trim() }
                    vm.provision(cfg, serverName)
                    onStarted()
                },
                enabled = !state.running && host.isNotBlank() &&
                    (if (useKey) pem.isNotBlank() else password.isNotBlank()),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.AuthSeg(text: String, selected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(9.dp),
        color = if (selected) Wisp else Color.Transparent,
        modifier = modifier,
    ) {
        Text(
            text,
            modifier = Modifier.padding(vertical = 8.dp),
            textAlign = TextAlign.Center,
            color = if (selected) Bg0 else Dim,
            style = MaterialTheme.typography.labelLarge,
        )
    }
}
