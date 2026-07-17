package dev.leshiy.ui.screens

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.leshiy.data.AppPrefs
import dev.leshiy.data.BatteryOptimization
import dev.leshiy.data.shouldPromptBattery
import dev.leshiy.ui.components.NavRow
import dev.leshiy.ui.components.PanelCard
import dev.leshiy.ui.components.ScreenFrame
import dev.leshiy.ui.components.SectionLabel
import dev.leshiy.ui.components.UpdateSettingsSection
import dev.leshiy.ui.i18n.Lang
import dev.leshiy.ui.i18n.LangState
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Bg0
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.Warn
import dev.leshiy.ui.theme.Wisp

@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onServers: () -> Unit,
    onSplit: () -> Unit,
    onDeploy: () -> Unit,
    onManage: () -> Unit,
    onCascade: () -> Unit,
    onVaultBackup: () -> Unit,
) {
    val s = LocalStrings.current
    val context = LocalContext.current
    val lang by LangState.lang.collectAsStateWithLifecycle()

    // Battery-exemption state, refreshed on resume so the checkmark updates after the system dialog.
    var batteryOk by remember { mutableStateOf(BatteryOptimization.isUnrestricted(context)) }
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val obs = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) batteryOk = BatteryOptimization.isUnrestricted(context)
        }
        lifecycleOwner.lifecycle.addObserver(obs)
        onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
    }

    ScreenFrame(s.settings, onBack = onBack) {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            SectionLabel(s.secConnection)
            NavRow(LeshiyIcons.Server, s.servers, s.serversSub, tint = Wisp, onClick = onServers)
            NavRow(LeshiyIcons.Shield, s.splitTunnel, s.splitSub, tint = Wisp, onClick = onSplit)

            Spacer(Modifier.size(6.dp))
            SectionLabel(s.secYourServers)
            NavRow(LeshiyIcons.Rocket, s.deploy, s.deploySub, tint = Wisp, onClick = onDeploy)
            NavRow(LeshiyIcons.Globe, s.buildCascade, s.cascadeSubtitle, tint = Wisp, onClick = onCascade)
            NavRow(LeshiyIcons.Gear, s.manage, s.manageSub, tint = Warn, onClick = onManage)
            NavRow(LeshiyIcons.File, s.vaultBackup, s.vaultBackupSub, tint = Wisp, onClick = onVaultBackup)

            Spacer(Modifier.size(6.dp))
            SectionLabel(s.secNetwork)
            var blockV6 by remember { mutableStateOf(AppPrefs.blockIpv6(context)) }
            PanelCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(s.blockIpv6Title, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground)
                        Text(s.blockIpv6Sub, style = MaterialTheme.typography.labelSmall, color = Dim)
                    }
                    Spacer(Modifier.size(12.dp))
                    Switch(
                        checked = blockV6,
                        onCheckedChange = { blockV6 = it; AppPrefs.setBlockIpv6(context, it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Bg0,
                            checkedTrackColor = Wisp,
                            uncheckedTrackColor = MaterialTheme.colorScheme.surface,
                            uncheckedBorderColor = MaterialTheme.colorScheme.outline,
                        ),
                    )
                }
            }

            Spacer(Modifier.size(6.dp))
            var sleepKa by remember { mutableStateOf(AppPrefs.sleepKeepalive(context)) }
            PanelCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(s.sleepKeepaliveTitle, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground)
                        Text(s.sleepKeepaliveSub, style = MaterialTheme.typography.labelSmall, color = Dim)
                    }
                    Spacer(Modifier.size(12.dp))
                    Switch(
                        checked = sleepKa,
                        onCheckedChange = {
                            sleepKa = it
                            AppPrefs.setSleepKeepalive(context, it)
                            // Keepalive is near-useless under Doze restriction — prompt for the
                            // exemption the moment it starts to matter.
                            if (shouldPromptBattery(it, BatteryOptimization.isUnrestricted(context))) {
                                BatteryOptimization.request(context)
                            }
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Bg0,
                            checkedTrackColor = Wisp,
                            uncheckedTrackColor = MaterialTheme.colorScheme.surface,
                            uncheckedBorderColor = MaterialTheme.colorScheme.outline,
                        ),
                    )
                }
            }

            Spacer(Modifier.size(6.dp))
            PanelCard(onClick = if (batteryOk) null else ({ BatteryOptimization.request(context) })) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(s.batteryTitle, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground)
                        Text(s.batterySub, style = MaterialTheme.typography.labelSmall, color = Dim)
                    }
                    Spacer(Modifier.size(12.dp))
                    Icon(
                        if (batteryOk) LeshiyIcons.Check else LeshiyIcons.ChevronRight,
                        contentDescription = null,
                        tint = if (batteryOk) Moss else Wisp,
                        modifier = Modifier.size(20.dp),
                    )
                }
            }

            Spacer(Modifier.size(6.dp))
            var reconnectBoot by remember { mutableStateOf(AppPrefs.reconnectOnBoot(context)) }
            PanelCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(s.reconnectBootTitle, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground)
                        Text(s.reconnectBootSub, style = MaterialTheme.typography.labelSmall, color = Dim)
                    }
                    Spacer(Modifier.size(12.dp))
                    Switch(
                        checked = reconnectBoot,
                        onCheckedChange = { reconnectBoot = it; AppPrefs.setReconnectOnBoot(context, it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Bg0,
                            checkedTrackColor = Wisp,
                            uncheckedTrackColor = MaterialTheme.colorScheme.surface,
                            uncheckedBorderColor = MaterialTheme.colorScheme.outline,
                        ),
                    )
                }
            }

            Spacer(Modifier.size(6.dp))
            NavRow(LeshiyIcons.Shield, s.alwaysOnTitle, s.alwaysOnSub, tint = Wisp, onClick = {
                // Opens Android's VPN settings, where the user enables system always-on + "block
                // connections without VPN". runCatching: some OEM ROMs don't resolve this action.
                runCatching {
                    context.startActivity(
                        Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    )
                }
            })

            Spacer(Modifier.size(6.dp))
            NavRow(LeshiyIcons.Info, s.notifSettingsTitle, s.notifSettingsSub, tint = Wisp, onClick = {
                // One-tap recovery when the running-VPN notification was denied — jumps straight to
                // this app's notification settings instead of the user hunting through Settings.
                runCatching {
                    context.startActivity(
                        Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                            .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    )
                }
            })

            Spacer(Modifier.size(6.dp))
            SectionLabel(s.language)
            Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surface, border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)) {
                Row(Modifier.padding(3.dp), horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                    LangSeg("English", lang == Lang.EN, Modifier.weight(1f)) { LangState.set(context, Lang.EN) }
                    LangSeg("Русский", lang == Lang.RU, Modifier.weight(1f)) { LangState.set(context, Lang.RU) }
                }
            }

            UpdateSettingsSection()
        }
    }
}

@Composable
private fun androidx.compose.foundation.layout.RowScope.LangSeg(text: String, selected: Boolean, modifier: Modifier, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(9.dp),
        color = if (selected) Wisp else Color.Transparent,
        modifier = modifier,
    ) {
        Text(
            text,
            modifier = Modifier.padding(vertical = 9.dp),
            textAlign = TextAlign.Center,
            color = if (selected) Bg0 else Dim,
            style = MaterialTheme.typography.labelLarge,
        )
    }
}
