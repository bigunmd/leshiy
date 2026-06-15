import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { setLanguage } from "./i18n";
import { api } from "@/lib/api";
import { defaultConfigName } from "@/lib/uri";
import { isVpn, isActiveState, needsHelper } from "@/lib/mode";
import { Atmosphere } from "@/components/Atmosphere";
import { ConnectScreen } from "@/components/ConnectScreen";
import { ConfigSheet } from "@/components/ConfigSheet";
import { SettingsSheet } from "@/components/SettingsSheet";
import { SplitTunnelSheet } from "@/components/SplitTunnelSheet";
import { PerAppSheet } from "@/components/PerAppSheet";
import { LanguageMenu } from "@/components/LanguageMenu";
import { InstallHelperDialog } from "@/components/InstallHelperDialog";
import { CloseWindowDialog } from "@/components/CloseWindowDialog";
import { useTunnel } from "@/state/useTunnel";
import { useProfiles } from "@/state/useProfiles";
import { useSettings } from "@/state/useSettings";

type SheetId = null | "config" | "settings" | "language" | "split" | "perapp";

export default function App() {
  const { t } = useTranslation();
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
  const [scanning, setScanning] = useState(false);
  const close = (o: boolean) => { if (!o) setSheet(null); };

  useEffect(() => { void api.helperInstalled().then(setHelperInstalled).catch(() => setHelperInstalled(false)); }, []);
  useEffect(() => { void api.platform().then(setPlatform).catch(() => setPlatform("")); }, []);

  // Report webview visibility to the backend so the ~1 Hz stats sampler parks when
  // the app is backgrounded (battery, especially Android). Fires on background/foreground.
  useEffect(() => {
    const report = () => void api.setForeground(!document.hidden).catch(() => {});
    report();
    document.addEventListener("visibilitychange", report);
    return () => document.removeEventListener("visibilitychange", report);
  }, []);

  // Report network connectivity so the supervisor parks reconnect backoff while
  // offline (battery). Sources: the webview's online/offline events (cross-platform)
  // and — authoritatively on Android — the VpnPlugin's ConnectivityManager event.
  useEffect(() => {
    const setOnline = (online: boolean) => void api.setOnline(online).catch(() => {});
    setOnline(navigator.onLine);
    const onOnline = () => setOnline(true);
    const onOffline = () => setOnline(false);
    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    let unlisten: (() => void) | undefined;
    void import("@tauri-apps/api/core")
      .then(({ addPluginListener }) =>
        addPluginListener("leshiy-vpn", "connectivity", (e: { online: boolean }) =>
          setOnline(e.online),
        ),
      )
      .then((h) => { unlisten = () => void h.unregister(); })
      .catch(() => {}); // desktop / plugin absent: navigator.onLine still drives it
    return () => {
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
      unlisten?.();
    };
  }, []);

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

  // Camera QR scan (Android). Owned here, not in ConfigSheet, so we can CLOSE the config sheet
  // first — otherwise the Radix sheet's focus-trap neutralizes the cancel overlay. The
  // barcode-scanner renders the camera behind a transparent webview, so `body.qr-scanning` hides
  // the app and the body-portaled `.qr-overlay` (the Cancel button) shows over the live camera.
  const onScanCamera = async () => {
    setSheet(null);
    const bc = await import("@tauri-apps/plugin-barcode-scanner");
    try {
      let perm = await bc.checkPermissions();
      if (perm !== "granted") perm = await bc.requestPermissions();
      if (perm !== "granted") return;
      document.body.classList.add("qr-scanning");
      setScanning(true);
      const res = await bc.scan({ formats: [bc.Format.QRCode], windowed: true });
      const v = res.content?.trim();
      if (v) await profiles.importProfile(v, defaultConfigName(v) || "config");
    } catch {
      /* cancelled or no code */
    } finally {
      document.body.classList.remove("qr-scanning");
      setScanning(false);
    }
  };
  const cancelScan = async () => {
    // Restore the UI IMMEDIATELY — do not wait on scan()'s promise (it may never resolve on
    // cancel, which would leave #root hidden over a transparent webview = a stuck white screen).
    document.body.classList.remove("qr-scanning");
    setScanning(false);
    try { const bc = await import("@tauri-apps/plugin-barcode-scanner"); await bc.cancel(); } catch { /* ignore */ }
  };

  // During a camera scan, render ONLY the cancel overlay (the camera shows behind the transparent
  // webview). The rest of the app — including any Radix sheet — is unmounted, which avoids the
  // sheet's focus-trap neutralizing the cancel button and the close-animation getting stuck
  // (the "invisible drawer" bug).
  if (scanning) {
    return (
      <div className="qr-overlay">
        <button
          onClick={cancelScan}
          className="rounded-full border border-wisp/60 bg-panel px-6 py-3 font-mono text-sm text-foreground shadow-lg"
        >
          {t("config.cancelScan")}
        </button>
      </div>
    );
  }

  return (
    <>
      <Atmosphere />
      <ConnectScreen
        state={state} rates={rates} active={profiles.active} mode={settings.mode} vpnDns={settings.vpn_dns} vpnMtu={settings.vpn_mtu}
        onToggle={onToggle} onModeChange={onModeChange}
        onOpenConfigs={() => setSheet("config")} onOpenSettings={() => setSheet("settings")} onOpenLanguage={() => setSheet("language")}
      />
      <ConfigSheet open={sheet === "config"} onOpenChange={close}
        profiles={profiles.profiles} activeId={profiles.activeId} canScanCamera={platform === "android"} onScanCamera={onScanCamera}
        onImport={profiles.importProfile} onSelect={profiles.select} onRemove={profiles.remove} onRename={profiles.rename} />
      <SettingsSheet open={sheet === "settings"} onOpenChange={close} settings={settings} onChange={update}
        helperInstalled={helperInstalled && !onDemand} onRemoveHelper={onRemoveHelper}
        isAndroid={platform === "android"}
        onOpenSplit={() => setSheet("split")}
        onOpenPerApp={() => setSheet("perapp")}
        onLanguageChange={(lng) => { setLanguage(lng); void update({ language: lng }); }} />
      <SplitTunnelSheet open={sheet === "split"} onOpenChange={close} value={settings.split_tunnel} subscriptions={settings.rule_subscriptions} onChange={update} />
      <PerAppSheet open={sheet === "perapp"} onOpenChange={close} value={settings.per_app} onChange={update} />
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
