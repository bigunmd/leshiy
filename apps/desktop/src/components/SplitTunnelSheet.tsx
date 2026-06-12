import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import { PRESETS } from "@/lib/presets";
import type { Settings, SplitCidr, SplitMode, SubFormat, Subscription, SubscriptionCache, SplitTunnel } from "@/lib/types";
import { ClipboardIcon } from "./icons";

interface Props {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  value: SplitTunnel;
  subscriptions: Subscription[];
  onChange: (patch: Partial<Settings>) => void;
}

const cidrKey = (c: SplitCidr) => `${c.addr}/${c.prefix}`;

export function SplitTunnelSheet(p: Props) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState("");
  const [format, setFormat] = useState<"lines" | "hosts">("lines");
  const [error, setError] = useState<string | null>(null);

  const setRules = (next: SplitTunnel) => p.onChange({ split_tunnel: next });
  const modes: SplitMode[] = ["exclude", "include"];

  // Merge a freshly-parsed ruleset into the current one (dedup), keeping the current mode.
  const merge = (add: SplitTunnel) => {
    const cidrs = [...p.value.cidrs];
    for (const c of add.cidrs) if (!cidrs.some((x) => cidrKey(x) === cidrKey(c))) cidrs.push(c);
    const domains = [...p.value.domains];
    for (const d of add.domains) if (!domains.includes(d)) domains.push(d);
    setRules({ ...p.value, cidrs, domains });
  };

  const addLine = async () => {
    setError(null);
    const line = draft.trim();
    if (!line) return;
    try {
      merge(await api.validateSplitRules(p.value.mode, "lines", line));
      setDraft("");
    } catch {
      setError(t("splitTunnel.invalid"));
    }
  };

  const importText = async (text: string) => {
    setError(null);
    if (!text.trim()) return;
    try {
      merge(await api.validateSplitRules(p.value.mode, format, text));
    } catch {
      setError(t("splitTunnel.invalid"));
    }
  };

  const removeCidr = (k: string) =>
    setRules({ ...p.value, cidrs: p.value.cidrs.filter((c) => cidrKey(c) !== k) });
  const removeDomain = (d: string) =>
    setRules({ ...p.value, domains: p.value.domains.filter((x) => x !== d) });

  // --- Subscriptions ---
  const [cache, setCache] = useState<SubscriptionCache>({ entries: {} });
  const [busy, setBusy] = useState<string | null>(null);
  const [showPresets, setShowPresets] = useState(false);
  const [customUrl, setCustomUrl] = useState("");
  const [customFmt, setCustomFmt] = useState<SubFormat>("lines");
  const [customMode, setCustomMode] = useState<SplitMode>("include");

  useEffect(() => {
    if (p.open) void api.subscriptionCache().then(setCache).catch(() => {});
  }, [p.open]);

  const setSubs = (subs: Subscription[]) => p.onChange({ rule_subscriptions: subs });
  const updateSub = (id: string, patch: Partial<Subscription>) =>
    setSubs(p.subscriptions.map((s) => (s.id === id ? { ...s, ...patch } : s)));
  const removeSub = (id: string) => setSubs(p.subscriptions.filter((s) => s.id !== id));
  const addSub = (s: Subscription) => {
    if (p.subscriptions.some((x) => x.id === s.id)) return; // already added
    setSubs([...p.subscriptions, s]);
  };
  const addCustom = () => {
    const url = customUrl.trim();
    if (!url) return;
    addSub({
      id: (crypto.randomUUID?.() ?? `custom-${Date.now()}`),
      name: url.split("/").pop() || url,
      url,
      format: customFmt,
      mode: customMode,
      enabled: true,
    });
    setCustomUrl("");
  };
  const refreshOne = async (id: string) => {
    setBusy(id);
    setError(null);
    try { setCache(await api.refreshSubscription(id)); }
    catch { setError(t("splitTunnel.invalid")); }
    finally { setBusy(null); }
  };
  const entryCount = (id: string) => {
    const e = cache.entries[id];
    return e ? e.rules.cidrs.length + e.rules.domains.length : 0;
  };

  const row = "flex items-center justify-between border-b border-border py-3";
  const empty = p.value.cidrs.length === 0 && p.value.domains.length === 0;

  return (
    <Sheet open={p.open} onOpenChange={p.onOpenChange}>
      <SheetContent side="bottom" className="bg-panel border-border max-h-[85%] overflow-y-auto rounded-t-2xl">
        <SheetHeader><SheetTitle>{t("splitTunnel.title")}</SheetTitle></SheetHeader>
        <div className="px-4 pb-6">
          {/* Mode pills */}
          <div className={row}>
            <span className="text-[13px]">{t("splitTunnel.mode")}</span>
            <div className="flex gap-1">
              {modes.map((m) => (
                <Button key={m} size="sm" variant={p.value.mode === m ? "secondary" : "ghost"}
                  onClick={() => setRules({ ...p.value, mode: m })}
                  className={cn("font-mono text-[10px] uppercase tracking-widest", p.value.mode === m ? "bg-moss text-foreground" : "text-dim")}>
                  {t(`splitTunnel.${m}`)}
                </Button>
              ))}
            </div>
          </div>
          <p className="mt-2 font-mono text-[10px] uppercase leading-relaxed tracking-widest text-dim/70">
            {t(p.value.mode === "exclude" ? "splitTunnel.excludeHint" : "splitTunnel.includeHint")}
          </p>

          {/* Add a single rule */}
          <div className="mt-4 flex gap-2">
            <Input className="flex-1 font-mono bg-bg1" placeholder={t("splitTunnel.addRule")} value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") void addLine(); }} />
            <Button onClick={addLine} disabled={!draft.trim()}>{t("splitTunnel.add")}</Button>
          </div>

          {/* Current rules */}
          <div className="mt-4 flex flex-col gap-3">
            {empty && <p className="text-dim text-[13px]">{t("splitTunnel.empty")}</p>}
            {p.value.cidrs.length > 0 && (
              <div>
                <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-dim/70">{t("splitTunnel.cidrs")}</div>
                <div className="flex flex-col gap-1.5">
                  {p.value.cidrs.map((c) => (
                    <div key={cidrKey(c)} className="flex items-center gap-2.5 rounded-lg border border-border bg-bg1 px-3 py-2">
                      <span className="flex-1 font-mono text-[13px] tabular-nums">{cidrKey(c)}</span>
                      <button aria-label={t("splitTunnel.remove")} className="font-mono text-xs text-warn"
                        onClick={() => removeCidr(cidrKey(c))}>✕</button>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {p.value.domains.length > 0 && (
              <div>
                <div className="mb-1 font-mono text-[10px] uppercase tracking-widest text-dim/70">{t("splitTunnel.domains")}</div>
                <div className="flex flex-col gap-1.5">
                  {p.value.domains.map((d) => (
                    <div key={d} className="flex items-center gap-2.5 rounded-lg border border-border bg-bg1 px-3 py-2">
                      <span className="flex-1 font-mono text-[13px]">{d}</span>
                      <button aria-label={t("splitTunnel.remove")} className="font-mono text-xs text-warn"
                        onClick={() => removeDomain(d)}>✕</button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Import */}
          <div className="mt-5 flex items-center gap-3">
            <span className="h-px flex-1 bg-border" />
            <span className="font-mono text-[10px] uppercase tracking-widest text-dim">{t("splitTunnel.import")}</span>
            <span className="h-px flex-1 bg-border" />
          </div>
          <div className="mt-3 flex items-center justify-between">
            <span className="font-mono text-[10px] uppercase tracking-widest text-dim/70">{t("splitTunnel.format")}</span>
            <div className="flex gap-1">
              {(["lines", "hosts"] as const).map((f) => (
                <Button key={f} size="sm" variant={format === f ? "secondary" : "ghost"} onClick={() => setFormat(f)}
                  className={cn("font-mono text-[10px] uppercase tracking-widest", format === f ? "bg-moss text-foreground" : "text-dim")}>
                  {t(f === "lines" ? "splitTunnel.formatLines" : "splitTunnel.formatHosts")}
                </Button>
              ))}
            </div>
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2.5">
            <button type="button"
              onClick={async () => {
                try { const text = await navigator.clipboard.readText(); if (text) await importText(text); }
                catch { /* clipboard blocked; use the file button */ }
              }}
              className="flex flex-col items-center justify-center gap-2 rounded-xl border border-border bg-bg1 py-4 transition hover:-translate-y-0.5 hover:border-wisp/60">
              <ClipboardIcon className="h-6 w-6 text-wisp" />
              <span className="text-xs text-foreground">{t("splitTunnel.fromClipboard")}</span>
            </button>
            <label className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border border-border bg-bg1 py-4 transition hover:-translate-y-0.5 hover:border-wisp/60">
              <span className="text-2xl leading-none text-wisp">⤓</span>
              <span className="text-xs text-foreground">{t("splitTunnel.fromFile")}</span>
              <input type="file" accept=".txt,text/plain" className="hidden"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  if (f) await importText(await f.text());
                  e.target.value = "";
                }} />
            </label>
          </div>
          {error && <div className="mt-3 text-warn text-xs">{error}</div>}

          {/* Subscriptions */}
          <div className="mt-6 flex items-center gap-3">
            <span className="h-px flex-1 bg-border" />
            <span className="font-mono text-[10px] uppercase tracking-widest text-dim">{t("splitTunnel.subscriptions")}</span>
            <span className="h-px flex-1 bg-border" />
          </div>

          <div className="mt-3 flex flex-col gap-1.5">
            {p.subscriptions.length === 0 && <p className="text-dim text-[13px]">{t("splitTunnel.noSubs")}</p>}
            {p.subscriptions.map((s) => (
              <div key={s.id} className="flex items-center gap-2.5 rounded-lg border border-border bg-bg1 px-3 py-2">
                <button aria-label="toggle" onClick={() => updateSub(s.id, { enabled: !s.enabled })}
                  className={cn("h-4 w-4 shrink-0 rounded-full border-2", s.enabled ? "border-wisp bg-wisp" : "border-moss")} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px]">{s.name}</div>
                  <div className="font-mono text-[10px] uppercase tracking-widest text-dim/70">
                    {t(`splitTunnel.${s.mode}`)} · {entryCount(s.id)} {t("splitTunnel.entries")}
                  </div>
                </div>
                <button className="font-mono text-[10px] uppercase tracking-widest text-moss disabled:opacity-50"
                  disabled={busy === s.id} onClick={() => void refreshOne(s.id)}>
                  {busy === s.id ? t("splitTunnel.refreshing") : t("splitTunnel.refresh")}
                </button>
                <button className="font-mono text-[10px] uppercase tracking-widest text-warn" onClick={() => removeSub(s.id)}>✕</button>
              </div>
            ))}
          </div>

          {/* Add preset */}
          <button onClick={() => setShowPresets((v) => !v)}
            className="mt-3 font-mono text-[10px] uppercase tracking-widest text-moss">
            {t("splitTunnel.addPreset")} {showPresets ? "▴" : "▾"}
          </button>
          {showPresets && (
            <div className="mt-2 flex flex-col gap-1.5">
              {PRESETS.map((preset) => {
                const added = p.subscriptions.some((s) => s.id === preset.id);
                return (
                  <div key={preset.id} className="flex items-center gap-2.5 rounded-lg border border-border bg-bg1 px-3 py-2">
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[13px]">{preset.name}</div>
                      <div className="font-mono text-[10px] uppercase tracking-widest text-dim/70">
                        {t(`splitTunnel.${preset.mode}`)} · {preset.license}
                      </div>
                    </div>
                    <Button size="sm" variant="ghost" disabled={added}
                      className="font-mono text-[10px] uppercase tracking-widest text-wisp disabled:opacity-40"
                      onClick={() => addSub({ ...preset, enabled: true })}>
                      {added ? t("splitTunnel.added") : t("splitTunnel.add")}
                    </Button>
                  </div>
                );
              })}
            </div>
          )}

          {/* Add custom URL */}
          <div className="mt-3 flex flex-col gap-2">
            <Input className="font-mono bg-bg1 text-xs" placeholder={t("splitTunnel.customUrl")} value={customUrl}
              onChange={(e) => setCustomUrl(e.target.value)} />
            <div className="flex items-center gap-2">
              <div className="flex gap-1">
                {(["lines", "hosts", "domainlist"] as const).map((f) => (
                  <Button key={f} size="sm" variant={customFmt === f ? "secondary" : "ghost"} onClick={() => setCustomFmt(f)}
                    className={cn("font-mono text-[10px] uppercase tracking-widest", customFmt === f ? "bg-moss text-foreground" : "text-dim")}>
                    {t(`splitTunnel.fmt_${f}`)}
                  </Button>
                ))}
              </div>
              <div className="flex gap-1">
                {(["include", "exclude"] as const).map((m) => (
                  <Button key={m} size="sm" variant={customMode === m ? "secondary" : "ghost"} onClick={() => setCustomMode(m)}
                    className={cn("font-mono text-[10px] uppercase tracking-widest", customMode === m ? "bg-moss text-foreground" : "text-dim")}>
                    {t(`splitTunnel.${m}`)}
                  </Button>
                ))}
              </div>
              <Button onClick={addCustom} disabled={!customUrl.trim()} className="ml-auto">{t("splitTunnel.add")}</Button>
            </div>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
