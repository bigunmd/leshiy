import { useState } from "react";
import { setLanguage } from "./i18n";
import { api } from "@/lib/api";
import { Atmosphere } from "@/components/Atmosphere";
import { ConnectScreen } from "@/components/ConnectScreen";
import { ConfigSheet } from "@/components/ConfigSheet";
import { SettingsSheet } from "@/components/SettingsSheet";
import { LanguageMenu } from "@/components/LanguageMenu";
import { useTunnel } from "@/state/useTunnel";
import { useProfiles } from "@/state/useProfiles";
import { useSettings } from "@/state/useSettings";

type SheetId = null | "config" | "settings" | "language";

export default function App() {
  const { state, rates } = useTunnel();
  const profiles = useProfiles();
  const { settings, update } = useSettings();
  const [sheet, setSheet] = useState<SheetId>(null);
  const close = (o: boolean) => { if (!o) setSheet(null); };

  const onToggle = () => {
    if (state === "Connected" || state === "Connecting" || state === "Reconnecting") void api.disconnect();
    else void api.connect();
  };

  return (
    <>
      <Atmosphere />
      <ConnectScreen
        state={state} rates={rates} active={profiles.active} mode={settings.mode} vpnDns={settings.vpn_dns}
        onToggle={onToggle} onModeChange={(m) => void update({ mode: m })}
        onOpenConfigs={() => setSheet("config")} onOpenSettings={() => setSheet("settings")} onOpenLanguage={() => setSheet("language")}
      />
      <ConfigSheet open={sheet === "config"} onOpenChange={close}
        profiles={profiles.profiles} activeId={profiles.activeId}
        onImport={profiles.importProfile} onSelect={profiles.select} onRemove={profiles.remove} onRename={profiles.rename} />
      <SettingsSheet open={sheet === "settings"} onOpenChange={close} settings={settings} onChange={update}
        helperInstalled={false} onRemoveHelper={() => {}}
        onLanguageChange={(lng) => { setLanguage(lng); void update({ language: lng }); }} />
      <LanguageMenu open={sheet === "language"} onOpenChange={close}
        onSelect={(lng) => { setLanguage(lng); void update({ language: lng }); }} />
    </>
  );
}
