import { useState } from "react";
import { createPortal } from "react-dom";
import { useTranslation } from "react-i18next";
import jsQR from "jsqr";
import { readText } from "@tauri-apps/plugin-clipboard-manager";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type { Profile } from "@/lib/types";
import { ClipboardIcon, QrIcon } from "./icons";
import { defaultConfigName } from "@/lib/uri";

interface Props {
  open: boolean; onOpenChange: (o: boolean) => void;
  profiles: Profile[]; activeId: string | null;
  onImport: (uri: string, name: string) => Promise<void>;
  onSelect: (id: string) => void; onRemove: (id: string) => void; onRename: (id: string, name: string) => void;
  /** Android: offer a live camera QR scan (the barcode-scanner plugin is mobile-only). */
  canScanCamera?: boolean;
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
  const [scanning, setScanning] = useState(false);
  const doImport = async () => {
    setError(null);
    try { await p.onImport(uri.trim(), name.trim() || defaultConfigName(uri) || "config"); setUri(""); setName(""); }
    catch { setError(t("config.invalid")); }
  };
  const setFromUri = (v: string) => { setUri(v); setName((n) => (n.trim() ? n : defaultConfigName(v))); };

  // Read the clipboard via the Tauri plugin (Android's webview blocks navigator.clipboard).
  const pasteFromClipboard = async () => {
    setError(null);
    try {
      const text = (await readText())?.trim();
      if (text) setFromUri(text);
    } catch {
      /* clipboard empty/blocked; the manual field still works */
    }
  };

  // Live camera QR scan (Android). The barcode-scanner renders the camera behind a transparent
  // webview, so we hide the app (body.qr-scanning) and show only a cancel control over the camera.
  const scanCamera = async () => {
    setError(null);
    const bc = await import("@tauri-apps/plugin-barcode-scanner");
    try {
      let perm = await bc.checkPermissions();
      if (perm !== "granted") perm = await bc.requestPermissions();
      if (perm !== "granted") { setError(t("config.cameraDenied")); return; }
      document.body.classList.add("qr-scanning");
      setScanning(true);
      const res = await bc.scan({ formats: [bc.Format.QRCode], windowed: true });
      const v = res.content?.trim();
      if (v) setFromUri(v); else setError(t("config.invalid"));
    } catch {
      setError(t("config.invalid"));
    } finally {
      document.body.classList.remove("qr-scanning");
      setScanning(false);
    }
  };
  const cancelScan = async () => {
    try { const bc = await import("@tauri-apps/plugin-barcode-scanner"); await bc.cancel(); } catch { /* ignore */ }
  };
  return (
    <Sheet open={p.open} onOpenChange={p.onOpenChange}>
      <SheetContent side="bottom" className="bg-panel border-border max-h-[80%] overflow-y-auto rounded-t-2xl">
        <SheetHeader><SheetTitle>{t("config.title")}</SheetTitle></SheetHeader>
        {/* Primary import: big icon buttons */}
        <div className={cn("grid gap-2.5 px-4 pt-1", p.canScanCamera ? "grid-cols-3" : "grid-cols-2")}>
          <button
            type="button"
            onClick={pasteFromClipboard}
            className="flex flex-col items-center justify-center gap-2 rounded-xl border border-border bg-bg1 py-5 transition hover:-translate-y-0.5 hover:border-wisp/60"
          >
            <ClipboardIcon className="h-7 w-7 text-wisp" />
            <span className="text-xs text-foreground">{t("config.fromClipboard")}</span>
          </button>
          {p.canScanCamera && (
            <button
              type="button"
              onClick={scanCamera}
              className="flex flex-col items-center justify-center gap-2 rounded-xl border border-border bg-bg1 py-5 transition hover:-translate-y-0.5 hover:border-wisp/60"
            >
              <QrIcon className="h-7 w-7 text-wisp" />
              <span className="text-xs text-foreground">{t("config.scanCamera")}</span>
            </button>
          )}
          <label className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border border-border bg-bg1 py-5 transition hover:-translate-y-0.5 hover:border-wisp/60">
            <QrIcon className="h-7 w-7 text-wisp" />
            <span className="text-xs text-foreground">{t("config.fromImage")}</span>
            <input
              type="file"
              accept="image/*"
              className="hidden"
              onChange={async (e) => {
                setError(null);
                const f = e.target.files?.[0];
                if (f) {
                  const decoded = await decodeQrFile(f);
                  if (decoded) setFromUri(decoded);
                  else setError(t("config.invalid"));
                }
              }}
            />
          </label>
        </div>
        {scanning &&
          createPortal(
            <div className="qr-overlay">
              <Button onClick={cancelScan} className="bg-panel">{t("config.cancelScan")}</Button>
            </div>,
            document.body,
          )}

        {/* Divider */}
        <div className="flex items-center gap-3 px-4 py-3">
          <span className="h-px flex-1 bg-border" />
          <span className="font-mono text-[10px] uppercase tracking-widest text-dim">{t("config.orPaste")}</span>
          <span className="h-px flex-1 bg-border" />
        </div>

        {/* Manual entry */}
        <div className="flex flex-col gap-2 px-4 pb-4">
          <Input className="font-mono bg-bg1" placeholder={t("config.paste")} value={uri} onChange={(e) => {
            const v = e.target.value;
            setUri(v);
            setName((n) => (n.trim() ? n : defaultConfigName(v)));
          }} />
          <div className="flex gap-2">
            <Input className="flex-1 bg-bg1" placeholder={t("config.name")} value={name} onChange={(e) => setName(e.target.value)} />
            <Button onClick={doImport} disabled={!uri.trim()}>{t("config.add")}</Button>
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
