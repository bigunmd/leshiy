import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Settings } from "@/lib/types";
const DEFAULTS: Settings = { language: "en", kill_switch: true, transport: "auto", socks_port: 1080, start_minimized: false };
export function useSettings() {
  const [settings, setSettings] = useState<Settings>(DEFAULTS);
  useEffect(() => { void api.getSettings().then(setSettings); }, []);
  const update = useCallback(async (patch: Partial<Settings>) => {
    const next = { ...settings, ...patch }; setSettings(next); await api.setSettings(next);
  }, [settings]);
  return { settings, update };
}
