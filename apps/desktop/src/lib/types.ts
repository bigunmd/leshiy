export type TunnelState = "Disconnected" | "Connecting" | "Connected" | "Reconnecting" | "Error";
export interface Rates { up_bps: number; down_bps: number; total_up: number; total_down: number; }
export interface Profile { id: string; name: string; uri: string; created_at: number; last_latency_ms: number | null; }
export type TransportPref = "auto" | "quic" | "tcp";
export type Mode = "proxy" | "vpn";
export interface Settings {
  language: string;
  kill_switch: boolean;
  transport: TransportPref;
  mode: Mode;
  vpn_mtu: number;
  vpn_dns: string;
  socks_port: number;
  start_minimized: boolean;
}
