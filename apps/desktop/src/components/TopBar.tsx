import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { ModePill } from "./ModePill";
import { WispMark, GearIcon } from "./icons";
import type { Mode } from "@/lib/types";
export function TopBar({ mode, onModeChange, onLanguage, onSettings }: { mode: Mode; onModeChange: (m: Mode) => void; onLanguage: () => void; onSettings: () => void }) {
  const { t, i18n } = useTranslation();
  return (
    <header className="flex items-center gap-2.5 px-[18px] py-4">
      <WispMark className="h-4 w-4 text-wisp" />
      <span className="font-bold tracking-[2px] text-sm">{t("brand")}</span>
      <span className="flex-1" />
      <ModePill mode={mode} onChange={onModeChange} />
      <Button variant="ghost" size="sm" onClick={onLanguage} className="font-mono text-[10px] tracking-widest text-dim">{i18n.language.toUpperCase()}</Button>
      <Button variant="ghost" size="icon" onClick={onSettings} aria-label="settings" className="text-dim"><GearIcon className="h-[18px] w-[18px]" /></Button>
    </header>
  );
}
