import { useTranslation } from "react-i18next";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { cn } from "@/lib/utils";
const LANGS = [{ code: "en", label: "English" }, { code: "ru", label: "Русский" }];
export function LanguageMenu({ open, onOpenChange, onSelect }: { open: boolean; onOpenChange: (o: boolean) => void; onSelect: (lng: string) => void }) {
  const { i18n } = useTranslation();
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="bottom" className="bg-panel border-border rounded-t-2xl">
        <SheetHeader><SheetTitle>Language / Язык</SheetTitle></SheetHeader>
        <div className="flex flex-col gap-2 px-4 pb-6">
          {LANGS.map((l) => (
            <button key={l.code} onClick={() => { onSelect(l.code); onOpenChange(false); }}
              className={cn("flex items-center gap-2.5 rounded-lg border border-border bg-bg1 px-3.5 py-3 text-sm", i18n.language === l.code && "border-l-[3px] border-l-wisp")}>
              {l.label}
            </button>
          ))}
        </div>
      </SheetContent>
    </Sheet>
  );
}
