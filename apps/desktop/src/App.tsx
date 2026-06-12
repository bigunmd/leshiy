import { useEffect, useState } from "react";
import { setLanguage } from "./i18n";
import { api } from "@/lib/api";
import { isVpn, isActiveState, needsHelper } from "@/lib/mode";
import { Atmosphere } from "@/components/Atmosphere";
import { ConnectScreen } from "@/components/ConnectScreen";
import { ConfigSheet } from "@/components/ConfigSheet";
import { SettingsSheet } from "@/components/SettingsSheet";
import { LanguageMenu } from "@/components/LanguageMenu";
import { InstallHelperDialog } from "@/components/InstallHelperDialog";
import { useTunnel } from "@/state/useTunnel";
import { useProfiles } from "@/state/useProfiles";
import { useSettings } from "@/state/useSettings";

type SheetId = null | "config" | "settings" | "language";

export default function App() {
  const { state, rates } = useTunnel();
  const profiles = useProfiles();
  const { settings, update } = useSettings();
  const [sheet, setSheet] = useState<SheetId>(null);
  const [installOpen, setInstallOpen] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [installError, setInstallError] = useState<string | null>(null);
  const [helperInstalled, setHelperInstalled] = useState(false);
  const [platform, setPlatform] = useState("");
  const close = (o: boolean) => { if (!o) setSheet(null); };

  useEffect(() => { void api.helperInstalled().then(setHelperInstalled).catch(() => setHelperInstalled(false)); }, []);
  useEffect(() => { void api.platform().then(setPlatform).catch(() => setPlatform("")); }, []);

  // All desktop platforms use the on-demand model: connect() itself triggers the OS elevation
  // prompt (pkexec / osascript / UAC), so there's no install dialog and no persistent helper
  // to remove. (`platform === ""` only before it loads.)
  const onDemand = platform !== "";

  const startConnect = () => { void api.connect(); };

  const onToggle = () => {
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
        state={state} rates={rates} active={profiles.active} mode={settings.mode} vpnDns={settings.vpn_dns}
        onToggle={onToggle} onModeChange={onModeChange}
        onOpenConfigs={() => setSheet("config")} onOpenSettings={() => setSheet("settings")} onOpenLanguage={() => setSheet("language")}
      />
      <ConfigSheet open={sheet === "config"} onOpenChange={close}
        profiles={profiles.profiles} activeId={profiles.activeId}
        onImport={profiles.importProfile} onSelect={profiles.select} onRemove={profiles.remove} onRename={profiles.rename} />
      <SettingsSheet open={sheet === "settings"} onOpenChange={close} settings={settings} onChange={update}
        helperInstalled={helperInstalled && !onDemand} onRemoveHelper={onRemoveHelper}
        onLanguageChange={(lng) => { setLanguage(lng); void update({ language: lng }); }} />
      <LanguageMenu open={sheet === "language"} onOpenChange={close}
        onSelect={(lng) => { setLanguage(lng); void update({ language: lng }); }} />
      <InstallHelperDialog open={installOpen} onOpenChange={setInstallOpen}
        installing={installing} error={installError}
        onNotNow={() => setInstallOpen(false)} onInstall={onInstall} />
    </>
  );
}
