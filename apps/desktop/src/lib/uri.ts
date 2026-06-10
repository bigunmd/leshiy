/** Derive a human-readable default config name from a leshiy:// URI: `host:port[SNI]`. */
export function defaultConfigName(uri: string): string {
  const u = uri.trim();
  const at = u.indexOf("@");
  if (at < 0) return "";
  const after = u.slice(at + 1);
  const host = after.split(/[?#]/)[0];
  if (!host) return "";
  const qi = after.indexOf("?");
  const sni = qi >= 0 ? new URLSearchParams(after.slice(qi + 1)).get("sni") : null;
  return sni ? `${host}[${sni}]` : host;
}
