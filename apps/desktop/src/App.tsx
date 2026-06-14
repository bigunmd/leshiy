import { useEffect, useRef, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { setLanguage } from "./i18n";
import { api } from "@/lib/api";
import { isVpn, isActiveState, needsHelper } from "@/lib/mode";
import { Atmosphere } from "@/components/Atmosphere";
import { ConnectScreen } from "@/components/ConnectScreen";
import { ConfigSheet } from "@/components/ConfigSheet";
import { SettingsSheet } from "@/components/SettingsSheet";
import { SplitTunnelSheet } from "@/components/SplitTunnelSheet";
import { LanguageMenu } from "@/components/LanguageMenu";
import { InstallHelperDialog } from "@/components/InstallHelperDialog";
import { CloseWindowDialog } from "@/components/CloseWindowDialog";
import { useTunnel } from "@/state/useTunnel";
import { useProfiles } from "@/state/useProfiles";
import { useSettings } from "@/state/useSettings";

type SheetId = null | "config" | "settings" | "language" | "split";

export default function App() {
  const { state, rates } = useTunnel();
  const profiles = useProfiles();
  const { settings, update } = useSettings();
  // The close-request handler is registered once but must read the *current*
  // preference, so mirror settings into a ref the closure can read.
  const settingsRef = useRef(settings);
  settingsRef.current = settings;
  const [sheet, setSheet] = useState<SheetId>(null);
  const [closeOpen, setCloseOpen] = useState(false);
  const [installOpen, setInstallOpen] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [installError, setInstallError] = useState<string | null>(null);
  const [helperInstalled, setHelperInstalled] = useState(false);
  const [platform, setPlatform] = useState("");
  const close = (o: boolean) => { if (!o) setSheet(null); };

  useEffect(() => { void api.helperInstalled().then(setHelperInstalled).catch(() => setHelperInstalled(false)); }, []);
  useEffect(() => { void api.platform().then(setPlatform).catch(() => setPlatform("")); }, []);

  // Intercept the window close: honor a remembered preference, otherwise prompt.
  // The frontend is the sole owner of close handling (the Rust side no longer hides).
  // Desktop-only: Android has no window close button / system tray (OS-managed lifecycle).
  useEffect(() => {
    if (!platform || platform === "android") return;
    const win = getCurrentWindow();
    let unlisten: (() => void) | undefined;
    void win.onCloseRequested((event) => {
      event.preventDefault();
      switch (settingsRef.current.close_behavior) {
        case "quit": void api.quit(); break;
        case "minimize": void api.hideToTray(); break;
        default: setCloseOpen(true); break;
      }
    }).then((u) => { unlisten = u; });
    return () => { unlisten?.(); };
  }, [platform]);

  const onCloseQuit = (remember: boolean) => {
    setCloseOpen(false);
    if (remember) { void update({ close_behavior: "quit" }).finally(() => void api.quit()); }
    else { void api.quit(); }
  };
  const onCloseMinimize = (remember: boolean) => {
    setCloseOpen(false);
    if (remember) void update({ close_behavior: "minimize" });
    void api.hideToTray();
  };

  // All desktop platforms use the on-demand model: connect() itself triggers the OS elevation
  // prompt (pkexec / osascript / UAC), so there's no install dialog and no persistent helper
  // to remove. (`platform === ""` only before it loads.)
  const onDemand = platform !== "";

  const startConnect = () => { void api.connect(); };

  const onToggle = () => {
    // Mid-teardown: ignore clicks so the route/DNS restore completes uninterrupted.
    if (state === "Disconnecting") return;
    if (isActiveState(state)) { void api.disconnect(); return; }
    // Linux only: if the daemon isn't installed yet, show the install dialog first.
    if (needsHelper(settings.mode) && !onDemand && !helperInstalled) { setInstallError(null); setInstallOpen(true); return; }
    startConnect();
  };

  const onInstall = async () => {
    setInstalling(true); setInstallError(null);
    try {
      await api.installHelper();
      setHelperInstalled(true);
      setInstallOpen(false);
      startConnect();
    } catch (e) {
      setInstallError(String(e));
    } finally {
      setInstalling(false);
    }
  };

  const onModeChange = (m: typeof settings.mode) => {
    // Flipping the pill is always free; if leaving VPN while connected, disconnect first.
    if (isVpn(settings.mode) && !isVpn(m) && isActiveState(state)) void api.disconnect();
    void update({ mode: m });
  };

  const onRemoveHelper = () => {
    void api.removeHelper().then(() => setHelperInstalled(false)).catch(() => {});
  };

  return (
    <>
      <Atmosphere />
      <ConnectScreen
        state={state} rates={rates} active={profiles.active} mode={settings.mode} vpnDns={settings.vpn_dns} vpnMtu={settings.vpn_mtu}
        onToggle={onToggle} onModeChange={onModeChange}
        onOpenConfigs={() => setSheet("config")} onOpenSettings={() => setSheet("settings")} onOpenLanguage={() => setSheet("language")}
      />
      <ConfigSheet open={sheet === "config"} onOpenChange={close}
        profiles={profiles.profiles} activeId={profiles.activeId} canScanCamera={platform === "android"}
        onImport={profiles.importProfile} onSelect={profiles.select} onRemove={profiles.remove} onRename={profiles.rename} />
      <SettingsSheet open={sheet === "settings"} onOpenChange={close} settings={settings} onChange={update}
        helperInstalled={helperInstalled && !onDemand} onRemoveHelper={onRemoveHelper}
        onOpenSplit={() => setSheet("split")}
        onLanguageChange={(lng) => { setLanguage(lng); void update({ language: lng }); }} />
      <SplitTunnelSheet open={sheet === "split"} onOpenChange={close} value={settings.split_tunnel} subscriptions={settings.rule_subscriptions} onChange={update} />
      <LanguageMenu open={sheet === "language"} onOpenChange={close}
        onSelect={(lng) => { setLanguage(lng); void update({ language: lng }); }} />
      <InstallHelperDialog open={installOpen} onOpenChange={setInstallOpen}
        installing={installing} error={installError}
        onNotNow={() => setInstallOpen(false)} onInstall={onInstall} />
      <CloseWindowDialog open={closeOpen} onOpenChange={setCloseOpen}
        onQuit={onCloseQuit} onMinimize={onCloseMinimize} />
    </>
  );
}
