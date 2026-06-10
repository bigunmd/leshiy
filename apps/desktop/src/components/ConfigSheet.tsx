import { useState } from "react";
import { useTranslation } from "react-i18next";
import jsQR from "jsqr";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type { Profile } from "@/lib/types";

interface Props {
  open: boolean; onOpenChange: (o: boolean) => void;
  profiles: Profile[]; activeId: string | null;
  onImport: (uri: string, name: string) => Promise<void>;
  onSelect: (id: string) => void; onRemove: (id: string) => void; onRename: (id: string, name: string) => void;
}

async function decodeQrFile(file: File): Promise<string | null> {
  const url = URL.createObjectURL(file);
  try {
    const img = await new Promise<HTMLImageElement>((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = rej; i.src = url; });
    const canvas = document.createElement("canvas"); canvas.width = img.width; canvas.height = img.height;
    const ctx = canvas.getContext("2d"); if (!ctx) return null;
    ctx.drawImage(img, 0, 0);
    const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
    return jsQR(data.data, data.width, data.height)?.data ?? null;
  } finally { URL.revokeObjectURL(url); }
}

export function ConfigSheet(p: Props) {
  const { t } = useTranslation();
  const [uri, setUri] = useState(""); const [name, setName] = useState(""); const [error, setError] = useState<string | null>(null);
  const doImport = async () => {
    setError(null);
    try { await p.onImport(uri.trim(), name.trim() || uri.trim().slice(9, 24)); setUri(""); setName(""); }
    catch { setError(t("config.invalid")); }
  };
  return (
    <Sheet open={p.open} onOpenChange={p.onOpenChange}>
      <SheetContent side="bottom" className="bg-panel border-border max-h-[80%] overflow-y-auto rounded-t-2xl">
        <SheetHeader><SheetTitle>{t("config.title")}</SheetTitle></SheetHeader>
        <div className="flex flex-col gap-2 px-4 pb-4">
          <Input className="font-mono bg-bg1" placeholder={t("config.paste")} value={uri} onChange={(e) => setUri(e.target.value)} />
          <div className="flex gap-2">
            <Input className="flex-1 bg-bg1" placeholder={t("config.name")} value={name} onChange={(e) => setName(e.target.value)} />
            <Button onClick={doImport} disabled={!uri.trim()}>{t("config.add")}</Button>
          </div>
          <div className="flex gap-4 text-[10px] uppercase tracking-widest">
            <button className="font-mono text-moss"
              onClick={async () => { try { setUri((await navigator.clipboard.readText()) ?? ""); } catch { /* ignore */ } }}>{t("config.fromClipboard")}</button>
            <label className="font-mono text-moss cursor-pointer">
              {t("config.fromImage")}
              <input type="file" accept="image/*" className="hidden"
                onChange={async (e) => { const f = e.target.files?.[0]; if (f) { const d = await decodeQrFile(f); d ? setUri(d) : setError(t("config.invalid")); } }} />
            </label>
          </div>
          {error && <div className="text-warn text-xs">{error}</div>}
        </div>
        <div className="flex flex-col gap-2 px-4 pb-6">
          {p.profiles.length === 0 && <p className="text-dim text-[13px]">{t("config.empty")}</p>}
          {p.profiles.map((profile) => {
            const isActive = profile.id === p.activeId;
            return (
              <div key={profile.id}
                className={cn("flex items-center gap-2.5 rounded-lg border border-border bg-bg1 px-3 py-2.5", isActive && "border-l-[3px] border-l-wisp")}>
                <button onClick={() => p.onSelect(profile.id)} aria-label="select"
                  className={cn("h-4 w-4 rounded-full border-2", isActive ? "border-wisp bg-wisp" : "border-moss")} />
                <span className="flex-1 text-[13px]">{profile.name}</span>
                <button className="font-mono text-[10px] uppercase tracking-widest text-dim"
                  onClick={() => { const n = prompt(t("config.rename") ?? "", profile.name); if (n) p.onRename(profile.id, n); }}>{t("config.rename")}</button>
                <button className="font-mono text-[10px] uppercase tracking-widest text-warn" onClick={() => p.onRemove(profile.id)}>{t("config.delete")}</button>
              </div>
            );
          })}
        </div>
      </SheetContent>
    </Sheet>
  );
}
