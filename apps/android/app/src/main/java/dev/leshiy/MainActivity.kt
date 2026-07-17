package dev.leshiy

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import dev.leshiy.data.AppPrefs
import dev.leshiy.data.Profiles
import dev.leshiy.data.shouldLock
import dev.leshiy.data.TunnelRepository
import dev.leshiy.data.UiEvents
import dev.leshiy.data.UiMessage
import dev.leshiy.data.UiMessageKind
import dev.leshiy.data.isFailureEdge
import dev.leshiy.ui.AppsViewModel
import dev.leshiy.ui.ConnectViewModel
import dev.leshiy.ui.ManageViewModel
import dev.leshiy.ui.ProfilesViewModel
import dev.leshiy.ui.ProvisionViewModel
import dev.leshiy.ui.QrScanActivity
import dev.leshiy.ui.SplitViewModel
import dev.leshiy.ui.components.Atmosphere
import dev.leshiy.ui.components.LeshiySnackbarHost
import dev.leshiy.ui.components.LeshiySnackbarVisuals
import dev.leshiy.ui.i18n.LangState
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.i18n.stringsFor
import dev.leshiy.ui.screens.CascadeBuilderScreen
import dev.leshiy.ui.screens.ConnectScreen
import dev.leshiy.ui.screens.CredentialScreen
import dev.leshiy.ui.screens.DeployScreen
import dev.leshiy.ui.screens.LockScreen
import dev.leshiy.ui.screens.ManageScreen
import dev.leshiy.ui.screens.OnboardingScreen
import dev.leshiy.ui.screens.ProvisioningScreen
import dev.leshiy.ui.screens.ServerDetailScreen
import dev.leshiy.ui.screens.ServerUsersScreen
import dev.leshiy.ui.screens.ServersScreen
import dev.leshiy.ui.screens.SettingsScreen
import dev.leshiy.ui.screens.SplitScreen
import dev.leshiy.ui.screens.UpgradeScreen
import dev.leshiy.ui.screens.VaultBackupScreen
import dev.leshiy.ui.theme.LeshiyTheme
import dev.leshiy.update.UpdateManager
import uniffi.leshiy_mobile.ConnState

class MainActivity : FragmentActivity() {

    private var pendingUri: String? = null

    /** App-lock UI gate. Read by [setContent]; the tunnel runs independently while locked. */
    private val locked = mutableStateOf(false)
    private var backgroundedAt = 0L
    private var sawFirstStart = false

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) pendingUri?.let(::startTunnel)
            pendingUri = null
        }

    // POST_NOTIFICATIONS is a runtime permission on Android 13+. Without it the foreground-service
    // status notification (with the Disconnect action) is silently suppressed — the tunnel still
    // runs, so we ignore the result and never block a connect on it.
    private val postNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* optional */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        LangState.init(this)
        UpdateManager.autoCheck(this)
        // Cold start: lock immediately if the feature is on (before any UI is shown).
        locked.value = AppPrefs.appLockEnabled(this)
        handleShortcut(intent)
        enableEdgeToEdge()
        setContent {
            val lang by LangState.lang.collectAsStateWithLifecycle()
            CompositionLocalProvider(LocalStrings provides stringsFor(lang)) {
                LeshiyTheme {
                    Atmosphere {
                        if (locked.value) {
                            LaunchedEffect(Unit) { promptUnlock() }
                            LockScreen(onUnlock = ::promptUnlock)
                            return@Atmosphere
                        }
                        var showOnboarding by remember {
                            mutableStateOf(
                                shouldShowOnboarding(
                                    complete = AppPrefs.onboardingComplete(this@MainActivity),
                                    hasAnyServer = hasAnyServer(),
                                ),
                            )
                        }
                        var startDest by remember { mutableStateOf(Route.CONNECT) }
                        if (showOnboarding) {
                            OnboardingScreen(
                                onFinish = { finishOnboarding(); startDest = Route.CONNECT; showOnboarding = false },
                                onAddServer = { finishOnboarding(); startDest = Route.SERVERS; showOnboarding = false },
                                onDeploy = { finishOnboarding(); startDest = Route.DEPLOY; showOnboarding = false },
                            )
                        } else {
                            AppNav(startDestination = startDest, onConnect = ::connect, onDisconnect = ::disconnect)
                        }
                    }
                }
            }
        }
    }

    private fun connect(uri: String) {
        if (uri.isEmpty()) return
        // Ask for notification permission in context (first connect) so the running-VPN status
        // notification is visible. Fire-and-forget: the tunnel does not depend on it.
        ensureNotificationPermission()
        val consent = VpnService.prepare(this)
        if (consent != null) {
            pendingUri = uri
            vpnConsent.launch(consent)
        } else {
            startTunnel(uri)
        }
    }

    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) postNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    private fun startTunnel(uri: String) {
        startService(Intent(this, LeshiyVpnService::class.java).putExtra(LeshiyVpnService.EXTRA_URI, uri))
    }

    private fun disconnect() {
        startService(Intent(this, LeshiyVpnService::class.java).setAction(LeshiyVpnService.ACTION_STOP))
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleShortcut(intent)
    }

    /** Perform a launcher-shortcut action. Connect/disconnect only touch the service — no UI is
     *  revealed, so this is safe to run while the app-lock screen is up. */
    private fun handleShortcut(intent: Intent?) {
        when (intent?.action) {
            ACTION_SHORTCUT_CONNECT ->
                runCatching { Profiles.manager(this).activeUri() }.getOrNull()?.let(::connect)
            ACTION_SHORTCUT_DISCONNECT -> disconnect()
        }
    }

    private fun hasAnyServer(): Boolean =
        runCatching { Profiles.manager(this).list().isNotEmpty() }.getOrDefault(false)

    private fun finishOnboarding() = AppPrefs.setOnboardingComplete(this, true)

    override fun onStop() {
        super.onStop()
        backgroundedAt = SystemClock.elapsedRealtime()
    }

    override fun onStart() {
        super.onStart()
        // The first onStart follows onCreate (cold start already handled there); only re-lock on a
        // genuine return from background, and only past the grace window.
        if (!sawFirstStart) {
            sawFirstStart = true
            return
        }
        val elapsed = SystemClock.elapsedRealtime() - backgroundedAt
        if (shouldLock(AppPrefs.appLockEnabled(this), elapsed)) locked.value = true
    }

    private fun promptUnlock() {
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    locked.value = false
                }
                // onAuthenticationError / failure: stay locked; the user retries via the button.
            },
        )
        val s = stringsFor(LangState.lang.value)
        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(s.lockTitle)
            .setSubtitle(s.lockPrompt)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Combined biometric + device-credential is only allowed together from API 30.
            builder.setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
        } else {
            builder.setAllowedAuthenticators(BIOMETRIC_STRONG)
            builder.setNegativeButtonText(s.lockCancel)
        }
        runCatching { prompt.authenticate(builder.build()) }
    }

    private companion object {
        const val ACTION_SHORTCUT_CONNECT = "dev.leshiy.SHORTCUT_CONNECT"
        const val ACTION_SHORTCUT_DISCONNECT = "dev.leshiy.SHORTCUT_DISCONNECT"
    }
}

private object Route {
    const val CONNECT = "connect"
    const val SETTINGS = "settings"
    const val SERVERS = "servers"
    const val SPLIT = "split"
    const val DEPLOY = "deploy"
    const val PROVISIONING = "provisioning"
    const val MANAGE = "manage"
    const val SERVER_DETAIL = "manage/server"
    const val SERVER_USERS = "manage/server/users"
    const val SERVER_UPGRADE = "manage/server/upgrade"
    const val CREDENTIAL = "manage/credential"
    const val CASCADE = "cascade"
    const val VAULT_BACKUP = "manage/backup"
}

@Composable
private fun AppNav(startDestination: String, onConnect: (String) -> Unit, onDisconnect: () -> Unit) {
    val nav = rememberNavController()
    val connectVm: ConnectViewModel = viewModel()
    val profilesVm: ProfilesViewModel = viewModel()
    val appsVm: AppsViewModel = viewModel()
    val splitVm: SplitViewModel = viewModel()
    val provisionVm: ProvisionViewModel = viewModel()
    val manageVm: ManageViewModel = viewModel()
    val upgradeVm: dev.leshiy.ui.UpgradeViewModel = viewModel()
    val cascadeVm: dev.leshiy.ui.CascadeViewModel = viewModel()
    val backupVm: dev.leshiy.ui.VaultBackupViewModel = viewModel()
    // True while DeployScreen/ProvisioningScreen are serving a cascade hop (vs a standalone deploy).
    var cascadeMode by remember { mutableStateOf(false) }

    // Holds a URI captured by the QR scanner until the Servers form consumes it.
    var scannedUri by remember { mutableStateOf("") }
    val qrLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.getStringExtra(QrScanActivity.EXTRA_URI)?.let { scannedUri = it }
        }
    }
    val context = androidx.compose.ui.platform.LocalContext.current

    // App-wide snackbar surface + failure wiring.
    val snackbarHost = remember { SnackbarHostState() }
    val strings by rememberUpdatedState(LocalStrings.current)
    LaunchedEffect(Unit) {
        UiEvents.messages.collect { msg ->
            snackbarHost.currentSnackbarData?.dismiss()
            snackbarHost.showSnackbar(LeshiySnackbarVisuals(msg.text, msg.kind))
        }
    }
    LaunchedEffect(Unit) {
        var prev: ConnState? = null
        TunnelRepository.status.collect { st ->
            val next = st?.state ?: ConnState.DISCONNECTED
            if (isFailureEdge(prev, next)) {
                UiEvents.emit(UiMessage(strings.connFailed, UiMessageKind.CONNECTION_FAILURE))
            }
            prev = next
        }
    }

    Box(Modifier.fillMaxSize()) {
    NavHost(nav, startDestination = startDestination) {
        composable(Route.CONNECT) {
            ConnectScreen(
                connectVm = connectVm,
                profilesVm = profilesVm,
                onConnect = onConnect,
                onDisconnect = onDisconnect,
                onOpenSettings = { nav.navigate(Route.SETTINGS) },
                onOpenServers = { nav.navigate(Route.SERVERS) },
            )
        }
        composable(Route.SETTINGS) {
            SettingsScreen(
                onBack = { nav.popBackStack() },
                onServers = { nav.navigate(Route.SERVERS) },
                onSplit = { nav.navigate(Route.SPLIT) },
                onDeploy = { nav.navigate(Route.DEPLOY) },
                onManage = { nav.navigate(Route.MANAGE) },
                onCascade = { cascadeVm.reset(); nav.navigate(Route.CASCADE) },
                onVaultBackup = { nav.navigate(Route.VAULT_BACKUP) },
            )
        }
        composable(Route.SERVERS) {
            ServersScreen(
                vm = profilesVm,
                scannedUri = scannedUri,
                onScan = { qrLauncher.launch(Intent(context, QrScanActivity::class.java)) },
                onConsumeScan = { scannedUri = "" },
                onBack = { nav.popBackStack() },
            )
        }
        composable(Route.SPLIT) {
            SplitScreen(appsVm = appsVm, splitVm = splitVm, onBack = { nav.popBackStack() })
        }
        composable(Route.DEPLOY) {
            DeployScreen(
                vm = provisionVm,
                onStarted = { nav.navigate(Route.PROVISIONING) },
                onBack = {
                    if (cascadeMode) { cascadeMode = false; cascadeVm.currentSlot.value = null }
                    nav.popBackStack()
                },
                preset = if (cascadeMode) cascadeVm.presetForCurrent(manageVm.servers.value) else null,
            )
        }
        composable(Route.PROVISIONING) {
            ProvisioningScreen(
                vm = provisionVm,
                onDone = { uri, label ->
                    if (cascadeMode) {
                        val slot = cascadeVm.currentSlot.value
                        val id = provisionVm.state.value.serverId
                        if (slot != null && id.isNotBlank()) cascadeVm.recordDeployed(slot, id)
                        provisionVm.reset()
                        manageVm.refreshServers()
                        val next = cascadeVm.beginNext()
                        if (next != null) {
                            // Deploy the next hop toward the entry.
                            nav.navigate(Route.DEPLOY) { popUpTo(Route.PROVISIONING) { inclusive = true } }
                        } else {
                            // Chain complete: the last deploy was the entry; its URI is the connect point.
                            cascadeMode = false
                            manageVm.presentCredential(label, uri)
                            nav.navigate(Route.CREDENTIAL) { popUpTo(Route.CASCADE) { inclusive = true } }
                        }
                    } else {
                        profilesVm.add(uri, label)
                        provisionVm.reset()
                        nav.popBackStack(Route.CONNECT, inclusive = false)
                    }
                },
                onBack = {
                    provisionVm.reset()
                    if (cascadeMode) cascadeMode = false
                    nav.popBackStack()
                },
            )
        }
        composable(Route.CASCADE) {
            CascadeBuilderScreen(
                vm = cascadeVm,
                manageVm = manageVm,
                onStartBuild = {
                    val slot = cascadeVm.beginNext()
                    if (slot != null) { cascadeMode = true; nav.navigate(Route.DEPLOY) }
                },
                onBack = { nav.popBackStack() },
            )
        }
        composable(Route.VAULT_BACKUP) {
            VaultBackupScreen(vm = backupVm, onBack = { nav.popBackStack() })
        }
        composable(Route.MANAGE) {
            ManageScreen(
                vm = manageVm,
                onOpenServer = { nav.navigate(Route.SERVER_DETAIL) },
                onBack = { nav.popBackStack() },
            )
        }
        composable(Route.SERVER_DETAIL) {
            ServerDetailScreen(
                vm = manageVm,
                upgradeVm = upgradeVm,
                onOpenUsers = { nav.navigate(Route.SERVER_USERS) },
                onOpenUpgrade = { nav.navigate(Route.SERVER_UPGRADE) },
                onBack = { nav.popBackStack() },
            )
        }
        composable(Route.SERVER_USERS) {
            ServerUsersScreen(
                vm = manageVm,
                onOpenCredential = { nav.navigate(Route.CREDENTIAL) },
                onBack = { nav.popBackStack() },
            )
        }
        composable(Route.SERVER_UPGRADE) {
            UpgradeScreen(
                vm = upgradeVm,
                // The vault record changed — without the refresh the Version card would come back
                // showing the old image ref.
                onDone = { manageVm.refreshServers(); nav.popBackStack() },
                onBack = {
                    // Leaving via the back arrow skips onDone — refresh here too, or a finished
                    // run leaves the Version card showing the stale imageRef until the vault is
                    // re-unlocked.
                    if (upgradeVm.state.value.done) manageVm.refreshServers()
                    nav.popBackStack()
                },
            )
        }
        composable(Route.CREDENTIAL) {
            CredentialScreen(
                vm = manageVm,
                onSaveToProfiles = { uri, label -> profilesVm.add(uri, label) },
                onBack = { nav.popBackStack() },
            )
        }
    }
        LeshiySnackbarHost(
            hostState = snackbarHost,
            onRetry = { runCatching { Profiles.manager(context).activeUri() }.getOrNull()?.let(onConnect) },
            onSwitch = { nav.navigate(Route.SERVERS) },
            modifier = Modifier.align(Alignment.BottomCenter),
        )
    }
}
