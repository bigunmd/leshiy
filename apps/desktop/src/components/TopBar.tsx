import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { WispMark, GearIcon } from "./icons";
export function TopBar({ onLanguage, onSettings }: { onLanguage: () => void; onSettings: () => void }) {
  const { t, i18n } = useTranslation();
  return (
    <header className="flex items-center gap-2.5 px-[18px] py-4">
      <WispMark className="h-4 w-4 text-wisp" />
      <span className="font-bold tracking-[2px] text-sm">{t("brand")}</span>
      <span className="flex-1" />
      <Button variant="ghost" size="sm" onClick={onLanguage} className="font-mono text-[10px] tracking-widest text-dim">{i18n.language.toUpperCase()}</Button>
      <Button variant="ghost" size="icon" onClick={onSettings} aria-label="settings" className="text-dim"><GearIcon className="h-[18px] w-[18px]" /></Button>
    </header>
  );
}
