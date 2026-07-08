package dev.leshiy

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import dev.leshiy.ui.AppsViewModel
import dev.leshiy.ui.ConnectViewModel
import dev.leshiy.ui.ManageViewModel
import dev.leshiy.ui.ProfilesViewModel
import dev.leshiy.ui.ProvisionViewModel
import dev.leshiy.ui.QrScanActivity
import dev.leshiy.ui.SplitViewModel
import dev.leshiy.ui.components.Atmosphere
import dev.leshiy.ui.i18n.LangState
import dev.leshiy.ui.i18n.LocalStrings
import dev.leshiy.ui.i18n.stringsFor
import dev.leshiy.ui.screens.ConnectScreen
import dev.leshiy.ui.screens.DeployScreen
import dev.leshiy.ui.screens.ManageScreen
import dev.leshiy.ui.screens.ProvisioningScreen
import dev.leshiy.ui.screens.ServersScreen
import dev.leshiy.ui.screens.SettingsScreen
import dev.leshiy.ui.screens.SplitScreen
import dev.leshiy.ui.theme.LeshiyTheme

class MainActivity : ComponentActivity() {

    private var pendingUri: String? = null

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) pendingUri?.let(::startTunnel)
            pendingUri = null
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        LangState.init(this)
        enableEdgeToEdge()
        setContent {
            val lang by LangState.lang.collectAsStateWithLifecycle()
            CompositionLocalProvider(LocalStrings provides stringsFor(lang)) {
                LeshiyTheme {
                    Atmosphere {
                        AppNav(onConnect = ::connect, onDisconnect = ::disconnect)
                    }
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
        startService(Intent(this, LeshiyVpnService::class.java).putExtra(LeshiyVpnService.EXTRA_URI, uri))
    }

    private fun disconnect() {
        startService(Intent(this, LeshiyVpnService::class.java).setAction(LeshiyVpnService.ACTION_STOP))
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
}

@Composable
private fun AppNav(onConnect: (String) -> Unit, onDisconnect: () -> Unit) {
    val nav = rememberNavController()
    val connectVm: ConnectViewModel = viewModel()
    val profilesVm: ProfilesViewModel = viewModel()
    val appsVm: AppsViewModel = viewModel()
    val splitVm: SplitViewModel = viewModel()
    val provisionVm: ProvisionViewModel = viewModel()
    val manageVm: ManageViewModel = viewModel()

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

    NavHost(nav, startDestination = Route.CONNECT) {
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
                onBack = { nav.popBackStack() },
            )
        }
        composable(Route.PROVISIONING) {
            ProvisioningScreen(
                vm = provisionVm,
                onDone = { uri, label ->
                    profilesVm.add(uri, label)
                    provisionVm.reset()
                    nav.popBackStack(Route.CONNECT, inclusive = false)
                },
                onBack = { provisionVm.reset(); nav.popBackStack() },
            )
        }
        composable(Route.MANAGE) {
            ManageScreen(
                vm = manageVm,
                onUserUri = { uri, label -> profilesVm.add(uri, label) },
                onBack = { nav.popBackStack() },
            )
        }
    }
}
