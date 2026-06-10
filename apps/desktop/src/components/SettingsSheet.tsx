import { useTranslation } from "react-i18next";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { Settings, TransportPref } from "@/lib/types";

interface Props {
  open: boolean; onOpenChange: (o: boolean) => void;
  settings: Settings; onChange: (patch: Partial<Settings>) => void; onLanguageChange: (lng: string) => void;
}
export function SettingsSheet(p: Props) {
  const { t, i18n } = useTranslation();
  const transports: TransportPref[] = ["auto", "quic", "tcp"];
  const row = "flex items-center justify-between border-b border-border py-3";
  return (
    <Sheet open={p.open} onOpenChange={p.onOpenChange}>
      <SheetContent side="bottom" className="bg-panel border-border max-h-[80%] overflow-y-auto rounded-t-2xl">
        <SheetHeader><SheetTitle>{t("settings.title")}</SheetTitle></SheetHeader>
        <div className="px-4 pb-6">
          <div className={row}>
            <Label className="text-[13px]">{t("settings.language")}</Label>
            <Select value={i18n.language} onValueChange={(v) => { if (v) p.onLanguageChange(v); }}>
              <SelectTrigger className="w-32 bg-bg1"><SelectValue /></SelectTrigger>
              <SelectContent><SelectItem value="en">English</SelectItem><SelectItem value="ru">Русский</SelectItem></SelectContent>
            </Select>
          </div>
          <div className={row}>
            <Label className="text-[13px]">{t("settings.killSwitch")}</Label>
            <Switch checked={p.settings.kill_switch} onCheckedChange={(v) => p.onChange({ kill_switch: v })} />
          </div>
          <div className={row}>
            <Label className="text-[13px]">{t("settings.transport")}</Label>
            <div className="flex gap-1">
              {transports.map((tr) => (
                <Button key={tr} size="sm" variant={p.settings.transport === tr ? "secondary" : "ghost"}
                  onClick={() => p.onChange({ transport: tr })}
                  className={cn("font-mono text-[10px] uppercase tracking-widest", p.settings.transport === tr ? "bg-moss text-foreground" : "text-dim")}>
                  {t(`settings.${tr}`)}
                </Button>
              ))}
            </div>
          </div>
          <div className={row}>
            <Label className="text-[13px]">{t("settings.socksPort")}</Label>
            <Input type="number" className="font-mono w-24 bg-bg1 text-right" value={p.settings.socks_port}
              onChange={(e) => p.onChange({ socks_port: Number(e.target.value) })} />
          </div>
          <p className="mt-3.5 font-mono text-[10px] uppercase leading-relaxed tracking-widest text-dim/70">{t("settings.restartNote")}</p>
        </div>
      </SheetContent>
    </Sheet>
  );
}
