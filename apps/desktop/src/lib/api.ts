import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { Profile, Rates, Settings, TunnelState } from "./types";

export const api = {
  listProfiles: () => invoke<Profile[]>("list_profiles"),
  activeProfile: () => invoke<Profile | null>("active_profile"),
  importProfile: (uri: string, name: string) => invoke<string>("import_profile", { uri, name }),
  removeProfile: (id: string) => invoke<void>("remove_profile", { id }),
  renameProfile: (id: string, name: string) => invoke<void>("rename_profile", { id, name }),
  setActive: (id: string) => invoke<void>("set_active", { id }),
  connect: () => invoke<void>("connect"),
  disconnect: () => invoke<void>("disconnect"),
  getSettings: () => invoke<Settings>("get_settings"),
  setSettings: (settings: Settings) => invoke<void>("set_settings", { settings }),
  helperInstalled: () => invoke<boolean>("helper_installed"),
  installHelper: () => invoke<void>("install_helper"),
};
export const onState = (cb: (s: TunnelState) => void): Promise<UnlistenFn> =>
  listen<TunnelState>("tunnel:state", (e) => cb(e.payload));
export const onStats = (cb: (r: Rates) => void): Promise<UnlistenFn> =>
  listen<Rates>("tunnel:stats", (e) => cb(e.payload));
