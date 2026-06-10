export type TunnelState = "Disconnected" | "Connecting" | "Connected" | "Reconnecting" | "Error";
export interface Rates { up_bps: number; down_bps: number; total_up: number; total_down: number; }
export interface Profile { id: string; name: string; uri: string; created_at: number; last_latency_ms: number | null; }
export type TransportPref = "auto" | "quic" | "tcp";
export interface Settings { language: string; kill_switch: boolean; transport: TransportPref; socks_port: number; start_minimized: boolean; }
