import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { Profile, Rates, Settings, SplitMode, SplitTunnel, SubscriptionCache, TunnelState } from "./types";

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
  validateSplitRules: (mode: SplitMode, format: "lines" | "hosts", text: string) =>
    invoke<SplitTunnel>("validate_split_rules", { mode, format, text }),
  subscriptionCache: () => invoke<SubscriptionCache>("subscription_cache"),
  refreshSubscriptions: () => invoke<SubscriptionCache>("refresh_subscriptions"),
  refreshSubscription: (id: string) => invoke<SubscriptionCache>("refresh_subscription", { id }),
  helperInstalled: () => invoke<boolean>("helper_installed"),
  installHelper: () => invoke<void>("install_helper"),
  removeHelper: () => invoke<void>("remove_helper"),
  platform: () => invoke<string>("platform"),
  quit: () => invoke<void>("quit_app"),
  hideToTray: () => invoke<void>("hide_window"),
};
export const onState = (cb: (s: TunnelState) => void): Promise<UnlistenFn> =>
  listen<TunnelState>("tunnel:state", (e) => cb(e.payload));
export const onStats = (cb: (r: Rates) => void): Promise<UnlistenFn> =>
  listen<Rates>("tunnel:stats", (e) => cb(e.payload));
