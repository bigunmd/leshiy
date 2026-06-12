import type { SubFormat, SplitMode } from "./types";

/// A built-in subscription preset. `license` is shown so users know which are unlicensed
/// (fetched at runtime, never bundled).
export interface Preset {
  id: string;
  name: string;
  url: string;
  format: SubFormat;
  mode: SplitMode;
  license: string;
}

// Curated for the Russia/TSPU audience (verified mid-2026). Include = "route through the VPN",
// Exclude = "keep off the VPN". Lists are fetched at runtime, never redistributed.
export const PRESETS: Preset[] = [
  {
    id: "refilter-domains",
    name: "Re:filter — RU-blocked domains",
    url: "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/domains_all.lst",
    format: "lines",
    mode: "include",
    license: "MIT",
  },
  {
    id: "refilter-ips",
    name: "Re:filter — RU-blocked IPs",
    url: "https://raw.githubusercontent.com/1andrevich/Re-filter-lists/main/ipsum.lst",
    format: "lines",
    mode: "include",
    license: "MIT",
  },
  {
    id: "itdog-discord",
    name: "itdoginfo — Discord IPs",
    url: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/discord.lst",
    format: "lines",
    mode: "include",
    license: "no license",
  },
  {
    id: "itdog-meta",
    name: "itdoginfo — Meta IPs",
    url: "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets/IPv4/meta.lst",
    format: "lines",
    mode: "include",
    license: "no license",
  },
  {
    id: "antifilter-allyouneed",
    name: "antifilter — RU-blocked IPs",
    url: "https://antifilter.download/list/allyouneed.lst",
    format: "lines",
    mode: "include",
    license: "no license",
  },
  {
    id: "stevenblack-hosts",
    name: "StevenBlack — ads & trackers",
    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    format: "hosts",
    mode: "exclude",
    license: "MIT",
  },
  {
    id: "ipverse-ru",
    name: "ipverse — all Russian IPs",
    url: "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/ipv4-aggregated.txt",
    format: "lines",
    mode: "exclude",
    license: "CC0",
  },
];
