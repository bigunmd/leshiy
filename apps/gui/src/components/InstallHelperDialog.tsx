import { useTranslation } from "react-i18next";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Button } from "@/components/ui/button";

interface Props {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  installing: boolean;
  error: string | null;
  onNotNow: () => void;
  onInstall: () => void;
}

export function InstallHelperDialog(p: Props) {
  const { t } = useTranslation();
  return (
    <Sheet open={p.open} onOpenChange={p.onOpenChange}>
      <SheetContent side="bottom" className="bg-panel border-border rounded-t-2xl">
        <SheetHeader><SheetTitle>{t("install.title")}</SheetTitle></SheetHeader>
        <div className="px-4 pb-6">
          <p className="text-[13px] leading-relaxed text-foreground/90">{t("install.body")}</p>
          <ul className="mt-3 space-y-1.5 text-[12px] leading-relaxed text-dim">
            <li className="flex gap-2"><span className="text-moss">•</span> {t("install.bullet1")}</li>
            <li className="flex gap-2"><span className="text-moss">•</span> {t("install.bullet2")}</li>
            <li className="flex gap-2"><span className="text-moss">•</span> {t("install.bullet3")}</li>
          </ul>
          {p.error && (
            <p className="mt-3 font-mono text-[11px] text-warn">{t("install.failed")}: {p.error}</p>
          )}
          <div className="mt-5 flex gap-2">
            <Button variant="ghost" className="flex-1 text-dim" onClick={p.onNotNow} disabled={p.installing}>{t("install.notNow")}</Button>
            <Button className="flex-1 bg-wisp text-bg0 hover:bg-wisp-bright" onClick={p.onInstall} disabled={p.installing}>
              {p.installing ? t("install.installing") : t("install.install")}
            </Button>
          </div>
          <p className="mt-3.5 font-mono text-[10px] uppercase leading-relaxed tracking-widest text-dim/70">{t("install.authNote")}</p>
        </div>
      </SheetContent>
    </Sheet>
  );
}
