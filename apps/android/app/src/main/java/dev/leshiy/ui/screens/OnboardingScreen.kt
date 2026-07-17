package dev.leshiy.ui.screens

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import dev.leshiy.ui.components.OutlineButton
import dev.leshiy.ui.components.PrimaryButton
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.icons.LeshiyIcons
import dev.leshiy.ui.theme.Bg0
import dev.leshiy.ui.theme.Dim
import dev.leshiy.ui.theme.Moss
import dev.leshiy.ui.theme.Panel
import dev.leshiy.ui.theme.Wisp
import kotlinx.coroutines.launch

private const val PAGES = 4

/**
 * First-run onboarding: a 4-slide pager shown only on a fresh install (see [shouldShowOnboarding]).
 * Explains what the app does, warms the user up for the VPN-consent dialog, actively guides the
 * reliability permissions (notifications / battery / always-on), and hands off to adding a server.
 *
 * @param onFinish complete onboarding and land on Connect.
 * @param onAddServer complete onboarding and open the add-server screen.
 * @param onDeploy complete onboarding and open the deploy-your-own screen.
 */
@Composable
fun OnboardingScreen(
    onFinish: () -> Unit,
    onAddServer: () -> Unit,
    onDeploy: () -> Unit,
) {
    val s = LocalStrings.current
    val context = LocalContext.current
    val pager = rememberPagerState(pageCount = { PAGES })
    val scope = rememberCoroutineScope()

    // Reliability-permission states, refreshed on resume so checkmarks update when the user returns
    // from a system settings screen.
    var notifGranted by remember { mutableStateOf(notificationsGranted(context)) }
    var batteryOk by remember { mutableStateOf(batteryUnrestricted(context)) }
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val obs = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                notifGranted = notificationsGranted(context)
                batteryOk = batteryUnrestricted(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(obs)
        onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
    }

    val requestNotif = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        notifGranted = it
    }

    Column(
        modifier = Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing),
    ) {
        HorizontalPager(state = pager, modifier = Modifier.weight(1f)) { page ->
            when (page) {
                0 -> Slide(s.obTitle1, s.obBody1) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(LeshiyIcons.Wisp, null, tint = Wisp, modifier = Modifier.size(22.dp))
                        Spacer(Modifier.width(10.dp))
                        Text("LESHIY", fontWeight = FontWeight.Bold, letterSpacing = 3.sp, fontSize = 22.sp, color = MaterialTheme.colorScheme.onBackground)
                    }
                }
                1 -> Slide(s.obTitle2, s.obBody2)
                2 -> Slide(s.obTitle3, s.obBody3) {
                    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        ActionRow(s.obAllowNotif, done = notifGranted) {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !notifGranted) {
                                requestNotif.launch(Manifest.permission.POST_NOTIFICATIONS)
                            }
                        }
                        ActionRow(s.obBattery, done = batteryOk) {
                            runCatching {
                                context.startActivity(
                                    Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                                )
                            }
                        }
                        ActionRow(s.obAlwaysOn, done = false) {
                            runCatching {
                                context.startActivity(
                                    Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                                )
                            }
                        }
                    }
                }
                else -> Slide(s.obTitle4, s.obBody4) {
                    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        PrimaryButton(s.obAddServer, onClick = onAddServer, modifier = Modifier.fillMaxWidth())
                        OutlineButton(s.obDeploy, onClick = onDeploy, modifier = Modifier.fillMaxWidth())
                    }
                }
            }
        }

        // Bottom bar: Skip · dots · Next / Finish.
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                s.obSkip,
                color = Dim,
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.clip(RoundedCornerShape(8.dp)).clickable(onClick = onFinish).padding(8.dp),
            )
            Spacer(Modifier.weight(1f))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                repeat(PAGES) { i ->
                    Box(
                        Modifier.size(if (i == pager.currentPage) 8.dp else 6.dp)
                            .clip(CircleShape)
                            .background(if (i == pager.currentPage) Wisp else Panel),
                    )
                }
            }
            Spacer(Modifier.weight(1f))
            val last = pager.currentPage == PAGES - 1
            PrimaryButton(if (last) s.obFinish else s.obNext, onClick = {
                if (last) onFinish() else scope.launch { pager.animateScrollToPage(pager.currentPage + 1) }
            })
        }
    }
}

/** One centered slide: title + body, with optional [extra] content below. */
@Composable
private fun Slide(title: String, body: String, extra: @Composable (() -> Unit)? = null) {
    Column(
        modifier = Modifier.fillMaxSize().padding(horizontal = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onBackground, textAlign = TextAlign.Center)
        Spacer(Modifier.size(14.dp))
        Text(body, style = MaterialTheme.typography.bodyMedium, color = Dim, textAlign = TextAlign.Center)
        if (extra != null) {
            Spacer(Modifier.size(26.dp))
            extra()
        }
    }
}

/** A tappable reliability action with a done/next affordance. */
@Composable
private fun ActionRow(label: String, done: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .clickable(enabled = !done, onClick = onClick)
            .background(Panel)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onBackground, modifier = Modifier.weight(1f))
        if (done) {
            Icon(LeshiyIcons.Check, null, tint = Moss, modifier = Modifier.size(20.dp))
        } else {
            Icon(LeshiyIcons.ChevronRight, null, tint = Wisp, modifier = Modifier.size(20.dp))
        }
    }
}

private fun notificationsGranted(context: android.content.Context): Boolean =
    Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
        context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

private fun batteryUnrestricted(context: android.content.Context): Boolean =
    (context.getSystemService(PowerManager::class.java))?.isIgnoringBatteryOptimizations(context.packageName) ?: false
