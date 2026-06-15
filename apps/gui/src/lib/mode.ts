import type { Mode, TunnelState } from "./types";

/** True when the app is in full-tunnel VPN mode. */
export const isVpn = (mode: Mode): boolean => mode === "vpn";

/** i18n key for the idle hint shown under the orb when disconnected, per mode. */
export function idleHintKey(mode: Mode): "mode.vpnHint" | "mode.proxyHint" {
  return mode === "vpn" ? "mode.vpnHint" : "mode.proxyHint";
}

/** Whether tapping Connect in this mode requires the privileged helper. */
export const needsHelper = (mode: Mode): boolean => mode === "vpn";

/** Treat these states as "busy/connected" for the connect/disconnect toggle. */
export function isActiveState(state: TunnelState): boolean {
  return state === "Connected" || state === "Connecting" || state === "Reconnecting";
}
