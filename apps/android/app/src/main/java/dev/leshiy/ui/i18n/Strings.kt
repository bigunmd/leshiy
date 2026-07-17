package dev.leshiy.ui.i18n

import android.content.Context
import androidx.compose.runtime.staticCompositionLocalOf
import kotlinx.coroutines.flow.MutableStateFlow
import java.util.Locale

enum class Lang(val tag: String) { EN("en"), RU("ru") }

/**
 * Typed UI string table. One implementation per language ([EnStrings]/[RuStrings]), selected via
 * [LocalStrings] and read as `s.foo`.
 *
 * An `interface` of abstract `val`s, deliberately not a `data class` with a big constructor: past
 * ~250 fields a constructor (and the generated `copy$default`) exceeds the JVM's 255-parameter
 * method limit (ClassFormatError). Abstract vals compile to individual getters with no such ceiling,
 * so this scales as strings are added. Add new keys here and override them in both objects below.
 */
interface Strings {
    // Connect
    val stProtected: String
    val stConnecting: String
    val stReconnecting: String
    val stError: String
    val stDisconnected: String
    val noServerSelected: String
    val chooseServer: String
    val manageServersLink: String
    // Settings hub
    val settings: String
    val secConnection: String
    val servers: String
    val serversSub: String
    val splitTunnel: String
    val splitSub: String
    val secYourServers: String
    val deploy: String
    val deploySub: String
    val manage: String
    val manageSub: String
    val language: String
    val langSystem: String
    val secNetwork: String
    val blockIpv6Title: String
    val blockIpv6Sub: String
    val sleepKeepaliveTitle: String
    val sleepKeepaliveSub: String
    val reconnectBootTitle: String
    val reconnectBootSub: String
    val alwaysOnTitle: String
    val alwaysOnSub: String
    val notifSettingsTitle: String
    val notifSettingsSub: String
    val obTitle1: String
    val obBody1: String
    val obTitle2: String
    val obBody2: String
    val obTitle3: String
    val obBody3: String
    val obAllowNotif: String
    val obBattery: String
    val obAlwaysOn: String
    val obTitle4: String
    val obBody4: String
    val obAddServer: String
    val obDeploy: String
    val obSkip: String
    val obNext: String
    val obFinish: String
    val connFailed: String
    val snRetry: String
    val snSwitchServer: String
    val snDismiss: String
    val updateFailedSnack: String
    val deployFailedSnack: String
    val batteryTitle: String
    val batterySub: String
    val secSecurity: String
    val appLockTitle: String
    val appLockSub: String
    val appLockNoBiometric: String
    val lockTitle: String
    val lockPrompt: String
    val lockUnlock: String
    val lockCancel: String
    // Servers
    val savedServers: String
    val noServers: String
    val active: String
    val tapToSelect: String
    val addServer: String
    val nameOptional: String
    val leshiyLink: String
    val addServerBtn: String
    val remove: String
    val scanQr: String
    val pasteClipboard: String
    // Split
    val byApp: String
    val byNetwork: String
    val modeOff: String
    val modeInclude: String
    val modeExclude: String
    val hintAppOff: String
    val hintAppInclude: String
    val hintAppExclude: String
    val hintNetOff: String
    val hintNetInclude: String
    val hintNetExclude: String
    val searchApps: String
    val apps: String
    val rules: String
    val ipCidrDomain: String
    val addRule: String
    val nothingYet: String
    val domainNote: String
    val excludeUnsupported: String
    val invalidRule: String
    // Deploy
    val deployIntro: String
    val target: String
    val vpsHost: String
    val sshUser: String
    val sshPassword: String
    val camouflage: String
    val borrowedSite: String
    val realityPort: String
    val provision: String
    val provisioning: String
    val progress: String
    // Manage
    val unlockVault: String
    val vaultPassphrase: String
    val unlock: String
    val wrongPassphrase: String
    // Vault backup
    val vaultBackup: String
    val vaultBackupSub: String
    val secExport: String
    val exportWarning: String
    val backupPassphrase: String
    val confirmBackupPassphrase: String
    val passphraseMismatch: String
    val exportAction: String
    val exportDone: String
    val noServersToExport: String
    val secImport: String
    val chooseBackupFile: String
    val importAction: String
    val importedServers: String
    val importedServersReplaced: String
    val noSavedServers: String
    val users: String
    val newUserLabel: String
    val checkStatus: String
    val teardown: String
    val sudoPasswordManage: String
    val sudoRequiredNote: String
    val sudoApply: String
    val serverStatus: String
    val statusUnknown: String
    val statusChecking: String
    val statusRunningLabel: String
    val statusStoppedLabel: String
    val statusErrorLabel: String
    val manageUsersSubtitle: String
    val addUser: String
    val showQr: String
    val credential: String
    val credentialHint: String
    val copyLink: String
    val copied: String
    val saveToProfiles: String
    val saved: String
    val savedToProfiles: String
    val share: String
    val orphan: String
    val statusRunning: String
    val statusStopped: String
    // Split file import
    val importFile: String
    val importedCount: String
    val importFailed: String
    // Deploy advanced + optional
    val sshPort: String
    val sudoPasswordOpt: String
    val serverLabelOpt: String
    val advanced: String
    val quicPortOpt: String
    val containerImageOpt: String
    val firstUserLabelOpt: String
    val dnsOverrideOpt: String
    // Deploy tooltips
    val helpHost: String
    val helpSshPort: String
    val helpSshUser: String
    val helpSshPassword: String
    val helpSudo: String
    val helpDest: String
    val helpListenPort: String
    val helpLabel: String
    val helpQuic: String
    val helpImage: String
    val helpUserLabel: String
    val helpDns: String
    val help: String
    // SSH auth
    val authPassword: String
    val authKey: String
    val sshPrivateKey: String
    val keyPassphraseOpt: String
    val loadKeyFile: String
    val helpKey: String
    val helpKeyPassphrase: String
    val keyEncryptedHint: String
    // Provisioning progress + vault setup
    val provisioningTitle: String
    val stepOf: String
    val serverReady: String
    val provisionFailed: String
    val goToServers: String
    val logs: String
    val saveForManagement: String
    val vaultUnlockedNote: String
    val vaultPassphraseOptDeploy: String
    val helpVaultDeploy: String
    // Cascade (multi-hop) builder
    val buildCascade: String
    val cascadeSubtitle: String
    val cascadeIntro: String
    val cascadeDeployBanner: String
    val internet: String
    val roleEntry: String
    val roleMiddle: String
    val roleExit: String
    val roleSingle: String
    val slotEntry: String
    val slotMiddle: String
    val slotExit: String
    val addMiddleHop: String
    val startBuilding: String
    val setSlot: String
    val sourceDeployNew: String
    val sourceUseMine: String
    val sourcePasteLink: String
    val pasteConnectorLink: String
    val noCandidates: String
    val cascades: String
    val connectHere: String
    val missingHop: String
    val buildingCascade: String
    val cascadeReady: String
    val doneAction: String
    // Common
    val back: String
    // Upgrade
    val version: String
    val updateAvailable: String
    val upToDate: String
    val upgradeServer: String
    val reapplyVersion: String
    val upgradingTitle: String
    val upgraded: String
    val upgradeFailed: String
    val upgradeTunnelNote: String
    val upgradeBusyNote: String
    val stepConnect: String
    val stepPullImage: String
    val stepRecreate: String
    val stepSave: String
    // Shade (notification + QS tile)
    val notifConnected: String
    val notifConnectedPlain: String
    val notifDisconnect: String
    // App update (in-app updater)
    val updSection: String
    val updNewVersionFmt: String
    val updDownload: String
    val updLater: String
    val updCheck: String
    val updChecking: String
    val updUpToDate: String
    val updDownloading: String
    val updVerifying: String
    val updInstall: String
    val updFailed: String
    val updCurrentFmt: String
    /** Localized role name for a wire role string. */
    fun roleName(role: String): String = when (role) {
        "entry" -> roleEntry
        "middle" -> roleMiddle
        "exit" -> roleExit
        else -> roleSingle
    }
}

val EnStrings: Strings = object : Strings {
    override val stProtected = "protected"
    override val stConnecting = "connecting"
    override val stReconnecting = "reconnecting"
    override val stError = "error"
    override val stDisconnected = "disconnected"
    override val noServerSelected = "no server selected"
    override val chooseServer = "Choose a server"
    override val manageServersLink = "manage servers"
    override val settings = "Settings"
    override val secConnection = "Connection"
    override val servers = "Servers"
    override val serversSub = "Import, choose and manage server profiles"
    override val splitTunnel = "Split tunnel"
    override val splitSub = "Route only chosen apps through the VPN"
    override val secYourServers = "Your servers"
    override val deploy = "Deploy a server"
    override val deploySub = "Provision a fresh VPS over SSH"
    override val manage = "Manage servers"
    override val manageSub = "Users, status and teardown"
    override val language = "Language"
    override val langSystem = "System"
    override val secNetwork = "Network"
    override val blockIpv6Title = "Block IPv6"
    override val blockIpv6Sub = "Strict no-leak: routes IPv6 into the tunnel. May break IPv6 sites (e.g. YouTube) — leave off unless you need it."
    override val sleepKeepaliveTitle = "Keep alive while asleep"
    override val sleepKeepaliveSub = "Holds the tunnel open while the screen is off, so tunnelled apps still get notifications. Wakes the phone briefly every 9 minutes — costs some battery. Off, the tunnel reconnects in about a second when you wake it."
    override val reconnectBootTitle = "Reconnect on boot"
    override val reconnectBootSub = "Reconnect the active server automatically after the phone restarts or the app updates. Needs VPN permission already granted."
    override val alwaysOnTitle = "Always-on VPN & kill switch"
    override val alwaysOnSub = "Open Android settings to make Leshiy always-on and block traffic when it is off. The system-managed way to stay protected — more reliable than reconnect-on-boot."
    override val notifSettingsTitle = "Notifications"
    override val notifSettingsSub = "Open notification settings. Needed to see the connection status and the disconnect button while connected."
    override val obTitle1 = "Welcome to Leshiy"
    override val obBody1 = "Reach the open internet from behind censorship. Your traffic is encrypted and looks like ordinary web browsing."
    override val obTitle2 = "How it protects you"
    override val obBody2 = "Leshiy routes your connection through a server you control, wrapped so it blends in with normal HTTPS. When you first connect, Android will ask you to allow a VPN — that's expected; tap OK."
    override val obTitle3 = "Stay connected"
    override val obBody3 = "A few optional settings keep the tunnel reliable and visible. You can change these later in Settings."
    override val obAllowNotif = "Allow notifications"
    override val obBattery = "Don't restrict battery"
    override val obAlwaysOn = "Always-on VPN"
    override val obTitle4 = "Add your first server"
    override val obBody4 = "Paste or scan a connection link someone shared, or deploy your own server in a couple of taps."
    override val obAddServer = "Add a server"
    override val obDeploy = "Deploy your own"
    override val obSkip = "Skip"
    override val obNext = "Next"
    override val obFinish = "Get started"
    override val connFailed = "Couldn't connect. The server didn't respond — check it's running, then retry."
    override val snRetry = "Retry"
    override val snSwitchServer = "Switch server"
    override val snDismiss = "Dismiss"
    override val updateFailedSnack = "Update check failed. Check your connection and try again."
    override val deployFailedSnack = "Deploy failed"
    override val batteryTitle = "Allow background activity"
    override val batterySub = "Let Leshiy run unrestricted so the tunnel survives sleep. Recommended if you use keep-alive."
    override val secSecurity = "Security"
    override val appLockTitle = "App lock"
    override val appLockSub = "Require your fingerprint or screen lock to open the app. The tunnel keeps running while locked."
    override val appLockNoBiometric = "Set up a fingerprint or screen lock first."
    override val lockTitle = "Unlock Leshiy"
    override val lockPrompt = "Confirm it's you to open the app."
    override val lockUnlock = "Unlock"
    override val lockCancel = "Cancel"
    override val savedServers = "Saved servers"
    override val noServers = "No servers yet. Paste a leshiy:// link or scan a QR code below."
    override val active = "active"
    override val tapToSelect = "tap to select"
    override val addServer = "Add a server"
    override val nameOptional = "Name (optional)"
    override val leshiyLink = "leshiy:// link"
    override val addServerBtn = "Add server"
    override val remove = "Remove"
    override val scanQr = "Scan QR"
    override val pasteClipboard = "Paste from clipboard"
    override val byApp = "By app"
    override val byNetwork = "By network"
    override val modeOff = "Off"
    override val modeInclude = "Include"
    override val modeExclude = "Exclude"
    override val hintAppOff = "All apps go through the VPN."
    override val hintAppInclude = "Only the checked apps go through the VPN."
    override val hintAppExclude = "Checked apps bypass the VPN; everything else is tunneled."
    override val hintNetOff = "All traffic goes through the VPN."
    override val hintNetInclude = "Only traffic to these networks and domains goes through the VPN."
    override val hintNetExclude = "Traffic to these networks and domains bypasses the VPN; everything else is tunneled."
    override val searchApps = "Search apps"
    override val apps = "Apps"
    override val rules = "Rules"
    override val ipCidrDomain = "IP, CIDR or domain"
    override val addRule = "Add rule"
    override val nothingYet = "Nothing yet. Add an IP/CIDR (10.0.0.0/8) or a domain (netflix.com) below."
    override val domainNote = "Domains are resolved to IP addresses when you connect. CDNs with changing IPs may not fully match."
    override val excludeUnsupported = "Exclude by IP needs Android 13+. On this device it falls back to full tunnel."
    override val invalidRule = "Not a valid IP, CIDR or domain"
    override val deployIntro = "Provision a fresh VPS into a leshiy server over SSH. You'll need root or sudo access."
    override val target = "Target"
    override val vpsHost = "VPS host or IP"
    override val sshUser = "SSH user"
    override val sshPassword = "SSH password"
    override val camouflage = "Camouflage"
    override val borrowedSite = "Borrowed TLS site (host:port)"
    override val realityPort = "REALITY port"
    override val provision = "Provision server"
    override val provisioning = "Provisioning…"
    override val progress = "Progress"
    override val unlockVault = "Unlock the server vault — an encrypted store holding SSH credentials for the servers you provision. Set a passphrase the first time; enter it to unlock later."
    override val vaultPassphrase = "Vault passphrase"
    override val unlock = "Unlock"
    override val wrongPassphrase = "Wrong passphrase"
    override val vaultBackup = "Vault backup"
    override val vaultBackupSub = "Export or import your saved servers"
    override val secExport = "Export"
    override val exportWarning = "The backup file contains the SSH credentials for your servers. Anyone with both the file and its passphrase can manage them. Keep it somewhere safe."
    override val backupPassphrase = "Backup passphrase"
    override val confirmBackupPassphrase = "Confirm backup passphrase"
    override val passphraseMismatch = "Passphrases don't match"
    override val exportAction = "Export backup"
    override val exportDone = "Backup exported"
    override val noServersToExport = "No saved servers to export yet."
    override val secImport = "Import"
    override val chooseBackupFile = "Choose backup file"
    override val importAction = "Import"
    // Label form, not "Imported %d servers": a one-server backup is the common migration case and
    // would render "Imported 1 servers". Russian sidesteps plural agreement the same way.
    override val importedServers = "Servers imported: %d"
    override val importedServersReplaced = "Servers imported: %d (replaced: %d)"
    override val noSavedServers = "No saved servers. Provision one from Deploy while the vault is unlocked, and it'll appear here."
    override val users = "Users"
    override val newUserLabel = "New user label"
    override val checkStatus = "Check status"
    override val teardown = "Teardown"
    override val sudoPasswordManage = "Sudo password"
    override val sudoRequiredNote = "This server runs as a sudo user. Enter its sudo password to manage it — it's kept for this session only, never saved."
    override val sudoApply = "Unlock management"
    override val serverStatus = "Status"
    override val statusUnknown = "Not checked"
    override val statusChecking = "Checking…"
    override val statusRunningLabel = "Running"
    override val statusStoppedLabel = "Stopped"
    override val statusErrorLabel = "Error"
    override val manageUsersSubtitle = "Issue or revoke device credentials"
    override val addUser = "Add user"
    override val showQr = "Show QR"
    override val credential = "Credential"
    override val credentialHint = "Scan this on the other device, or copy / share the link."
    override val copyLink = "Copy"
    override val copied = "Copied to clipboard"
    override val saveToProfiles = "Save"
    override val saved = "Saved"
    override val savedToProfiles = "Saved to your servers"
    override val share = "Share"
    override val orphan = "(orphan)"
    override val statusRunning = "running"
    override val statusStopped = "stopped"
    override val importFile = "Import from file"
    override val importedCount = "Imported %d rules"
    override val importFailed = "Couldn't read that file"
    override val sshPort = "SSH port"
    override val sudoPasswordOpt = "Sudo password (optional)"
    override val serverLabelOpt = "Server label (optional)"
    override val advanced = "Advanced"
    override val quicPortOpt = "QUIC port (optional)"
    override val containerImageOpt = "Container image (optional)"
    override val firstUserLabelOpt = "First user label (optional)"
    override val dnsOverrideOpt = "DNS override (optional)"
    override val helpHost = "The public IP or hostname of the VPS you're setting up."
    override val helpSshPort = "Port your VPS accepts SSH on. Usually 22."
    override val helpSshUser = "SSH login user. Use root, or a sudo user plus the sudo password below."
    override val helpSshPassword = "Password for the SSH user. Used once to set up; never stored on the server."
    override val helpSudo = "Only if the SSH user isn't root. Lets setup run privileged commands via sudo."
    override val helpDest = "A real HTTPS site to imitate (host:port). Traffic looks like a visit to it. Pick a big, unrelated site."
    override val helpListenPort = "Port clients connect to. 443 blends in with normal HTTPS."
    override val helpLabel = "A friendly name for this server in your list. Defaults to the host."
    override val helpQuic = "Also serve over QUIC (UDP) on this port. Leave empty for TCP only."
    override val helpImage = "Override the server container image. Leave empty to match this app's version."
    override val helpUserLabel = "Name for the first client credential this creates. Defaults to \"self\"."
    override val helpDns = "Force the server's DNS resolver, e.g. 1.1.1.1. Leave empty to auto-detect."
    override val help = "Help"
    override val authPassword = "Password"
    override val authKey = "SSH key"
    override val sshPrivateKey = "Private key (PEM)"
    override val keyPassphraseOpt = "Key passphrase (optional)"
    override val loadKeyFile = "Load key from file"
    override val helpKey = "Paste your OpenSSH/PEM private key, or load it from a file. It's used once to set up and stored only in the encrypted vault."
    override val helpKeyPassphrase = "If your private key is encrypted, its passphrase. Leave empty otherwise."
    override val keyEncryptedHint = "This key is encrypted — enter its passphrase above."
    override val provisioningTitle = "Provisioning"
    override val stepOf = "Step %1\$d of %2\$d"
    override val serverReady = "Server ready"
    override val provisionFailed = "Provisioning failed"
    override val goToServers = "Add to servers"
    override val logs = "Logs"
    override val saveForManagement = "Save for management"
    override val vaultUnlockedNote = "This server will be saved to your unlocked vault, so you can manage it later."
    override val vaultPassphraseOptDeploy = "Vault passphrase (optional)"
    override val helpVaultDeploy = "Set a passphrase to save this server (with its SSH credentials) in an encrypted vault, so you can add users, check status or tear it down later. Leave empty to just get a client config."
    override val buildCascade = "Build a cascade"
    override val cascadeSubtitle = "Chain servers into a multi-hop tunnel"
    override val cascadeIntro = "Chain your phone through several servers. Traffic hops entry → … → exit before reaching the internet. Deploy the exit first — each hop is wired to the next automatically."
    override val cascadeDeployBanner = "Deploying the %1\$s of your cascade → next hop: %2\$s"
    override val internet = "the internet"
    override val roleEntry = "Entry"
    override val roleMiddle = "Middle"
    override val roleExit = "Exit"
    override val roleSingle = "Single"
    override val slotEntry = "Entry · you connect here"
    override val slotMiddle = "Middle · relay hop"
    override val slotExit = "Exit · reaches the internet"
    override val addMiddleHop = "Add middle hop"
    override val startBuilding = "Start building"
    override val setSlot = "Set"
    override val sourceDeployNew = "Deploy a new server here"
    override val sourceUseMine = "Use one of my servers"
    override val sourcePasteLink = "Paste a connector link"
    override val pasteConnectorLink = "Connector link (leshiy://…)"
    override val noCandidates = "No eligible servers — deploy one or paste a link."
    override val cascades = "Cascades"
    override val connectHere = "connect here"
    override val missingHop = "missing hop"
    override val buildingCascade = "Building cascade"
    override val cascadeReady = "Cascade ready"
    override val doneAction = "Done"
    override val back = "Back"
    override val version = "Version"
    override val updateAvailable = "Update available"
    override val upToDate = "Up to date"
    override val upgradeServer = "Upgrade server"
    override val reapplyVersion = "Re-apply %1\$s"
    override val upgradingTitle = "Upgrading"
    override val upgraded = "Upgraded to %1\$s"
    override val upgradeFailed = "Upgrade failed"
    override val upgradeTunnelNote = "The tunnel through this server drops briefly while the container is recreated. Users and keys are kept."
    override val upgradeBusyNote = "Another server is upgrading. Wait for it to finish."
    override val stepConnect = "Connect"
    override val stepPullImage = "Pull image"
    override val stepRecreate = "Recreate container"
    override val stepSave = "Save"
    override val notifConnected = "Connected — %1\$s"
    override val notifConnectedPlain = "Connected"
    override val notifDisconnect = "Disconnect"
    override val updSection = "App update"
    override val updNewVersionFmt = "New version %s available"
    override val updDownload = "Download"
    override val updLater = "Later"
    override val updCheck = "Check for updates"
    override val updChecking = "Checking…"
    override val updUpToDate = "Up to date"
    override val updDownloading = "Downloading…"
    override val updVerifying = "Verifying…"
    override val updInstall = "Install"
    override val updFailed = "Couldn't reach GitHub"
    override val updCurrentFmt = "Current version %s"
}

val RuStrings: Strings = object : Strings {
    override val stProtected = "под защитой"
    override val stConnecting = "подключение"
    override val stReconnecting = "переподключение"
    override val stError = "ошибка"
    override val stDisconnected = "отключено"
    override val noServerSelected = "сервер не выбран"
    override val chooseServer = "Выберите сервер"
    override val manageServersLink = "управление серверами"
    override val settings = "Настройки"
    override val secConnection = "Подключение"
    override val servers = "Серверы"
    override val serversSub = "Импорт, выбор и управление профилями серверов"
    override val splitTunnel = "Раздельный туннель"
    override val splitSub = "Пропускать через VPN только выбранные приложения"
    override val secYourServers = "Ваши серверы"
    override val deploy = "Развернуть сервер"
    override val deploySub = "Настроить новый VPS по SSH"
    override val manage = "Управление серверами"
    override val manageSub = "Пользователи, статус и удаление"
    override val language = "Язык"
    override val langSystem = "Системный"
    override val secNetwork = "Сеть"
    override val blockIpv6Title = "Блокировать IPv6"
    override val blockIpv6Sub = "Строгий режим без утечек: направляет IPv6 в туннель. Может ломать сайты на IPv6 (напр. YouTube) — включайте только при необходимости."
    override val sleepKeepaliveTitle = "Держать соединение во сне"
    override val sleepKeepaliveSub = "Не даёт туннелю закрыться при выключенном экране, чтобы приложения в туннеле продолжали получать уведомления. Ненадолго будит телефон каждые 9 минут — расходует батарею. Если выключено, туннель переподключится примерно за секунду после пробуждения."
    override val reconnectBootTitle = "Переподключаться при загрузке"
    override val reconnectBootSub = "Автоматически переподключать активный сервер после перезагрузки телефона или обновления приложения. Требуется уже выданное разрешение VPN."
    override val alwaysOnTitle = "Постоянный VPN и блокировка"
    override val alwaysOnSub = "Открыть настройки Android, чтобы сделать Leshiy постоянным и блокировать трафик, когда он выключен. Системный способ оставаться под защитой — надёжнее, чем переподключение при загрузке."
    override val notifSettingsTitle = "Уведомления"
    override val notifSettingsSub = "Открыть настройки уведомлений. Нужны, чтобы видеть статус подключения и кнопку отключения во время работы."
    override val obTitle1 = "Добро пожаловать в Leshiy"
    override val obBody1 = "Доступ к свободному интернету в обход цензуры. Ваш трафик зашифрован и выглядит как обычный веб-сёрфинг."
    override val obTitle2 = "Как это защищает вас"
    override val obBody2 = "Leshiy направляет соединение через ваш собственный сервер, маскируя его под обычный HTTPS. При первом подключении Android попросит разрешить VPN — это нормально, нажмите ОК."
    override val obTitle3 = "Оставайтесь на связи"
    override val obBody3 = "Несколько необязательных настроек делают туннель надёжным и заметным. Их можно изменить позже в настройках."
    override val obAllowNotif = "Разрешить уведомления"
    override val obBattery = "Не ограничивать батарею"
    override val obAlwaysOn = "Постоянный VPN"
    override val obTitle4 = "Добавьте первый сервер"
    override val obBody4 = "Вставьте или отсканируйте ссылку, которой с вами поделились, либо разверните свой сервер в пару нажатий."
    override val obAddServer = "Добавить сервер"
    override val obDeploy = "Развернуть свой"
    override val obSkip = "Пропустить"
    override val obNext = "Далее"
    override val obFinish = "Начать"
    override val connFailed = "Не удалось подключиться. Сервер не ответил — проверьте, что он запущен, и повторите."
    override val snRetry = "Повторить"
    override val snSwitchServer = "Сменить сервер"
    override val snDismiss = "Закрыть"
    override val updateFailedSnack = "Не удалось проверить обновления. Проверьте соединение и повторите."
    override val deployFailedSnack = "Развёртывание не удалось"
    override val batteryTitle = "Разрешить работу в фоне"
    override val batterySub = "Позвольте Leshiy работать без ограничений, чтобы туннель переживал сон. Рекомендуется при использовании keep-alive."
    override val secSecurity = "Безопасность"
    override val appLockTitle = "Блокировка приложения"
    override val appLockSub = "Требовать отпечаток или блокировку экрана для открытия приложения. Туннель продолжает работать при блокировке."
    override val appLockNoBiometric = "Сначала настройте отпечаток или блокировку экрана."
    override val lockTitle = "Разблокировать Leshiy"
    override val lockPrompt = "Подтвердите, что это вы, чтобы открыть приложение."
    override val lockUnlock = "Разблокировать"
    override val lockCancel = "Отмена"
    override val savedServers = "Сохранённые серверы"
    override val noServers = "Пока нет серверов. Вставьте ссылку leshiy:// или отсканируйте QR-код ниже."
    override val active = "активный"
    override val tapToSelect = "нажмите, чтобы выбрать"
    override val addServer = "Добавить сервер"
    override val nameOptional = "Название (необязательно)"
    override val leshiyLink = "ссылка leshiy://"
    override val addServerBtn = "Добавить сервер"
    override val remove = "Удалить"
    override val scanQr = "Сканировать QR"
    override val pasteClipboard = "Вставить из буфера"
    override val byApp = "По приложениям"
    override val byNetwork = "По сети"
    override val modeOff = "Выкл"
    override val modeInclude = "Включить"
    override val modeExclude = "Исключить"
    override val hintAppOff = "Все приложения идут через VPN."
    override val hintAppInclude = "Через VPN идут только отмеченные приложения."
    override val hintAppExclude = "Отмеченные приложения идут в обход VPN, остальные — через туннель."
    override val hintNetOff = "Весь трафик идёт через VPN."
    override val hintNetInclude = "Через VPN идёт только трафик к этим сетям и доменам."
    override val hintNetExclude = "Трафик к этим сетям и доменам идёт в обход VPN, остальной — через туннель."
    override val searchApps = "Поиск приложений"
    override val apps = "Приложения"
    override val rules = "Правила"
    override val ipCidrDomain = "IP, CIDR или домен"
    override val addRule = "Добавить правило"
    override val nothingYet = "Пока пусто. Добавьте IP/CIDR (10.0.0.0/8) или домен (netflix.com) ниже."
    override val domainNote = "Домены преобразуются в IP-адреса при подключении. CDN с меняющимися IP могут совпадать не полностью."
    override val excludeUnsupported = "Исключение по IP требует Android 13+. На этом устройстве используется полный туннель."
    override val invalidRule = "Некорректный IP, CIDR или домен"
    override val deployIntro = "Настройка нового VPS в сервер leshiy по SSH. Нужен доступ root или sudo."
    override val target = "Сервер"
    override val vpsHost = "Хост или IP VPS"
    override val sshUser = "Пользователь SSH"
    override val sshPassword = "Пароль SSH"
    override val camouflage = "Маскировка"
    override val borrowedSite = "Чужой TLS-сайт (host:port)"
    override val realityPort = "Порт REALITY"
    override val provision = "Развернуть сервер"
    override val provisioning = "Развёртывание…"
    override val progress = "Ход выполнения"
    override val unlockVault = "Разблокируйте хранилище серверов — зашифрованное хранилище с SSH-данными для развёрнутых серверов. Задайте пароль при первом запуске; вводите его для разблокировки позже."
    override val vaultPassphrase = "Пароль хранилища"
    override val unlock = "Разблокировать"
    override val wrongPassphrase = "Неверный пароль"
    override val vaultBackup = "Резервная копия хранилища"
    override val vaultBackupSub = "Экспорт и импорт сохранённых серверов"
    override val secExport = "Экспорт"
    override val exportWarning = "Файл резервной копии содержит SSH-данные ваших серверов. Тот, у кого есть файл и пароль к нему, сможет ими управлять. Храните его в надёжном месте."
    override val backupPassphrase = "Пароль резервной копии"
    override val confirmBackupPassphrase = "Повторите пароль"
    override val passphraseMismatch = "Пароли не совпадают"
    override val exportAction = "Экспортировать"
    override val exportDone = "Резервная копия сохранена"
    override val noServersToExport = "Пока нет сохранённых серверов для экспорта."
    override val secImport = "Импорт"
    override val chooseBackupFile = "Выбрать файл"
    override val importAction = "Импортировать"
    override val importedServers = "Импортировано серверов: %d"
    override val importedServersReplaced = "Импортировано серверов: %d (заменено: %d)"
    override val noSavedServers = "Нет сохранённых серверов. Разверните сервер во вкладке «Развернуть», пока хранилище разблокировано, и он появится здесь."
    override val users = "Пользователи"
    override val newUserLabel = "Название нового пользователя"
    override val checkStatus = "Проверить статус"
    override val teardown = "Удалить"
    override val sudoPasswordManage = "Пароль sudo"
    override val sudoRequiredNote = "Этот сервер работает под sudo-пользователем. Введите пароль sudo для управления — он хранится только для текущего сеанса и не сохраняется."
    override val sudoApply = "Разблокировать управление"
    override val serverStatus = "Статус"
    override val statusUnknown = "Не проверено"
    override val statusChecking = "Проверка…"
    override val statusRunningLabel = "Работает"
    override val statusStoppedLabel = "Остановлен"
    override val statusErrorLabel = "Ошибка"
    override val manageUsersSubtitle = "Выдать или отозвать данные устройств"
    override val addUser = "Добавить пользователя"
    override val showQr = "Показать QR"
    override val credential = "Данные доступа"
    override val credentialHint = "Отсканируйте на другом устройстве или скопируйте / поделитесь ссылкой."
    override val copyLink = "Копировать"
    override val copied = "Скопировано в буфер"
    override val saveToProfiles = "Сохранить"
    override val saved = "Сохранено"
    override val savedToProfiles = "Сохранено в ваши серверы"
    override val share = "Поделиться"
    override val orphan = "(без метки)"
    override val statusRunning = "работает"
    override val statusStopped = "остановлен"
    override val importFile = "Импорт из файла"
    override val importedCount = "Импортировано правил: %d"
    override val importFailed = "Не удалось прочитать файл"
    override val sshPort = "Порт SSH"
    override val sudoPasswordOpt = "Пароль sudo (необязательно)"
    override val serverLabelOpt = "Название сервера (необязательно)"
    override val advanced = "Дополнительно"
    override val quicPortOpt = "Порт QUIC (необязательно)"
    override val containerImageOpt = "Образ контейнера (необязательно)"
    override val firstUserLabelOpt = "Название первого пользователя (необязательно)"
    override val dnsOverrideOpt = "Переопределение DNS (необязательно)"
    override val helpHost = "Публичный IP или имя хоста VPS, который вы настраиваете."
    override val helpSshPort = "Порт SSH на вашем VPS. Обычно 22."
    override val helpSshUser = "Пользователь для входа по SSH. Root или sudo-пользователь с паролем sudo ниже."
    override val helpSshPassword = "Пароль SSH-пользователя. Используется один раз при настройке; на сервере не хранится."
    override val helpSudo = "Только если SSH-пользователь не root. Позволяет настройке выполнять команды через sudo."
    override val helpDest = "Настоящий HTTPS-сайт для маскировки (host:port). Трафик выглядит как визит на него. Выберите крупный посторонний сайт."
    override val helpListenPort = "Порт для подключения клиентов. 443 сливается с обычным HTTPS."
    override val helpLabel = "Понятное имя сервера в списке. По умолчанию — хост."
    override val helpQuic = "Дополнительно раздавать через QUIC (UDP) на этом порту. Пусто — только TCP."
    override val helpImage = "Переопределить образ контейнера сервера. Пусто — под версию приложения."
    override val helpUserLabel = "Имя первого клиентского доступа. По умолчанию «self»."
    override val helpDns = "Задать DNS-резолвер сервера, напр. 1.1.1.1. Пусто — автоопределение."
    override val help = "Справка"
    override val authPassword = "Пароль"
    override val authKey = "SSH-ключ"
    override val sshPrivateKey = "Приватный ключ (PEM)"
    override val keyPassphraseOpt = "Пароль ключа (необязательно)"
    override val loadKeyFile = "Загрузить ключ из файла"
    override val helpKey = "Вставьте приватный ключ OpenSSH/PEM или загрузите из файла. Используется один раз при настройке и хранится только в зашифрованном хранилище."
    override val helpKeyPassphrase = "Если ключ зашифрован — его пароль. Иначе оставьте пустым."
    override val keyEncryptedHint = "Ключ зашифрован — введите пароль выше."
    override val provisioningTitle = "Развёртывание"
    override val stepOf = "Шаг %1\$d из %2\$d"
    override val serverReady = "Сервер готов"
    override val provisionFailed = "Развёртывание не удалось"
    override val goToServers = "Добавить в серверы"
    override val logs = "Журнал"
    override val saveForManagement = "Сохранить для управления"
    override val vaultUnlockedNote = "Сервер будет сохранён в разблокированное хранилище, чтобы им можно было управлять позже."
    override val vaultPassphraseOptDeploy = "Пароль хранилища (необязательно)"
    override val helpVaultDeploy = "Задайте пароль, чтобы сохранить сервер (с его SSH-данными) в зашифрованном хранилище — тогда позже можно добавлять пользователей, проверять статус и удалять его. Пусто — только клиентский конфиг."
    override val buildCascade = "Собрать каскад"
    override val cascadeSubtitle = "Цепочка серверов в многоузловой туннель"
    override val cascadeIntro = "Пропустите трафик телефона через несколько серверов: вход → … → выход, и только потом в интернет. Сначала разверните выход — каждый узел подключается к следующему автоматически."
    override val cascadeDeployBanner = "Разворачивается %1\$s каскада → следующий узел: %2\$s"
    override val internet = "интернет"
    override val roleEntry = "Вход"
    override val roleMiddle = "Средний"
    override val roleExit = "Выход"
    override val roleSingle = "Одиночный"
    override val slotEntry = "Вход · сюда подключаетесь вы"
    override val slotMiddle = "Средний · промежуточный узел"
    override val slotExit = "Выход · выход в интернет"
    override val addMiddleHop = "Добавить средний узел"
    override val startBuilding = "Начать сборку"
    override val setSlot = "Задать"
    override val sourceDeployNew = "Развернуть новый сервер"
    override val sourceUseMine = "Выбрать из моих серверов"
    override val sourcePasteLink = "Вставить ссылку-коннектор"
    override val pasteConnectorLink = "Ссылка-коннектор (leshiy://…)"
    override val noCandidates = "Нет подходящих серверов — разверните новый или вставьте ссылку."
    override val cascades = "Каскады"
    override val connectHere = "подключение здесь"
    override val missingHop = "узел отсутствует"
    override val buildingCascade = "Сборка каскада"
    override val cascadeReady = "Каскад готов"
    override val doneAction = "Готово"
    override val back = "Назад"
    override val version = "Версия"
    override val updateAvailable = "Доступно обновление"
    override val upToDate = "Актуальная версия"
    override val upgradeServer = "Обновить сервер"
    override val reapplyVersion = "Переустановить %1\$s"
    override val upgradingTitle = "Обновление"
    override val upgraded = "Обновлено до %1\$s"
    override val upgradeFailed = "Не удалось обновить"
    override val upgradeTunnelNote = "Туннель через этот сервер ненадолго прервётся, пока контейнер пересоздаётся. Пользователи и ключи сохранятся."
    override val upgradeBusyNote = "Сейчас обновляется другой сервер. Дождитесь завершения."
    override val stepConnect = "Подключение"
    override val stepPullImage = "Загрузка образа"
    override val stepRecreate = "Пересоздание контейнера"
    override val stepSave = "Сохранение"
    override val notifConnected = "Подключено — %1\$s"
    override val notifConnectedPlain = "Подключено"
    override val notifDisconnect = "Отключить"
    override val updSection = "Обновление приложения"
    override val updNewVersionFmt = "Доступна новая версия %s"
    override val updDownload = "Скачать"
    override val updLater = "Позже"
    override val updCheck = "Проверить обновления"
    override val updChecking = "Проверка…"
    override val updUpToDate = "Установлена последняя версия"
    override val updDownloading = "Загрузка…"
    override val updVerifying = "Проверка файла…"
    override val updInstall = "Установить"
    override val updFailed = "Не удалось связаться с GitHub"
    override val updCurrentFmt = "Текущая версия %s"
}

fun stringsFor(lang: Lang): Strings = if (lang == Lang.RU) RuStrings else EnStrings

val LocalStrings = staticCompositionLocalOf { EnStrings }

/** Process-wide selected language, persisted; defaults to the device locale on first run. */
object LangState {
    val lang = MutableStateFlow(Lang.EN)

    fun init(context: Context) {
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val stored = prefs.getString("lang", null)
        lang.value = when (stored) {
            "en" -> Lang.EN
            "ru" -> Lang.RU
            else -> if (Locale.getDefault().language == "ru") Lang.RU else Lang.EN
        }
    }

    fun set(context: Context, value: Lang) {
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .edit().putString("lang", value.tag).apply()
        lang.value = value
    }
}
