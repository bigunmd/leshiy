import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { api } from "@/lib/api";
import type { AppInfo, PerAppMode, PerAppRules, Settings } from "@/lib/types";

interface Props {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  value: PerAppRules;
  onChange: (patch: Partial<Settings>) => void;
}

/** Android per-app split tunnel: choose which apps' traffic the VPN captures. */
export function PerAppSheet(p: Props) {
  const { t } = useTranslation();
  const [apps, setApps] = useState<AppInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState("");
  const modes: PerAppMode[] = ["off", "include", "exclude"];

  useEffect(() => {
    if (!p.open) return;
    setLoading(true);
    api
      .listApps()
      .then((a) => setApps([...a].sort((x, y) => x.label.localeCompare(y.label))))
      .catch(() => setApps([]))
      .finally(() => setLoading(false));
  }, [p.open]);

  const set = (patch: Partial<PerAppRules>) => p.onChange({ per_app: { ...p.value, ...patch } });
  const togglePkg = (pkg: string) => {
    const has = p.value.packages.includes(pkg);
    set({ packages: has ? p.value.packages.filter((x) => x !== pkg) : [...p.value.packages, pkg] });
  };
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? apps.filter((a) => a.label.toLowerCase().includes(q) || a.package.toLowerCase().includes(q)) : apps;
  }, [apps, query]);
  const active = p.value.mode !== "off";

  return (
    <Sheet open={p.open} onOpenChange={p.onOpenChange}>
      <SheetContent side="bottom" className="bg-panel border-border max-h-[85%] overflow-y-auto rounded-t-2xl">
        <SheetHeader><SheetTitle>{t("perApp.title")}</SheetTitle></SheetHeader>
        <div className="px-4 pb-6">
          <div className="flex items-center justify-between border-b border-border py-3">
            <span className="text-[13px]">{t("perApp.mode")}</span>
            <div className="flex gap-1">
              {modes.map((m) => (
                <Button key={m} size="sm" variant={p.value.mode === m ? "secondary" : "ghost"}
                  onClick={() => set({ mode: m })}
                  className={cn("font-mono text-[10px] uppercase tracking-widest", p.value.mode === m ? "bg-moss text-foreground" : "text-dim")}>
                  {t(`perApp.${m}`)}
                </Button>
              ))}
            </div>
          </div>
          <p className="mt-2 font-mono text-[10px] uppercase leading-relaxed tracking-widest text-dim/70">
            {t(`perApp.${p.value.mode}Hint`)}
          </p>
          {active && (
            <>
              <Input className="mt-3 bg-bg1" placeholder={t("perApp.search")} value={query} onChange={(e) => setQuery(e.target.value)} />
              {loading ? (
                <p className="mt-3 text-dim text-[13px]">{t("perApp.loading")}</p>
              ) : (
                <div className="mt-2 flex flex-col">
                  {filtered.map((a) => {
                    const checked = p.value.packages.includes(a.package);
                    return (
                      <button key={a.package} type="button" onClick={() => togglePkg(a.package)}
                        className="flex items-center gap-3 border-b border-border py-2.5 text-left">
                        <span className={cn("grid h-4 w-4 shrink-0 place-items-center rounded border text-[10px]", checked ? "border-wisp bg-wisp text-bg0" : "border-moss")}>
                          {checked ? "✓" : ""}
                        </span>
                        <span className="flex-1 truncate text-[13px]">{a.label}</span>
                        <span className="max-w-[40%] truncate font-mono text-[10px] text-dim/60">{a.package}</span>
                      </button>
                    );
                  })}
                </div>
              )}
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
