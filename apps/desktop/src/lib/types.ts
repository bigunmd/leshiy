export type TunnelState = "Disconnected" | "Connecting" | "Connected" | "Reconnecting" | "Error";
export interface Rates { up_bps: number; down_bps: number; total_up: number; total_down: number; }
export interface Profile { id: string; name: string; uri: string; created_at: number; last_latency_ms: number | null; }
export type TransportPref = "auto" | "quic" | "tcp";
export type Mode = "proxy" | "vpn";
export type CloseBehavior = "ask" | "quit" | "minimize";
export type SplitMode = "exclude" | "include";
export interface SplitCidr { addr: string; prefix: number; }
export interface SplitTunnel { mode: SplitMode; cidrs: SplitCidr[]; domains: string[]; }
export type SubFormat = "lines" | "hosts" | "domainlist";
export interface Subscription { id: string; name: string; url: string; format: SubFormat; mode: SplitMode; enabled: boolean; }
export interface SubRuleSet { cidrs: SplitCidr[]; domains: string[]; }
export interface SubscriptionCacheEntry { rules: SubRuleSet; etag: string | null; last_modified: string | null; fetched_at: number; }
export interface SubscriptionCache { entries: Record<string, SubscriptionCacheEntry>; }
export interface Settings {
  language: string;
  kill_switch: boolean;
  transport: TransportPref;
  mode: Mode;
  vpn_mtu: number;
  vpn_dns: string;
  socks_port: number;
  start_minimized: boolean;
  close_behavior: CloseBehavior;
  split_tunnel: SplitTunnel;
  rule_subscriptions: Subscription[];
}
