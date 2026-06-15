import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { Mode } from "@/lib/types";

const MODES: Mode[] = ["proxy", "vpn"];

export function ModePill({ mode, onChange }: { mode: Mode; onChange: (m: Mode) => void }) {
  const { t } = useTranslation();
  return (
    <div className="flex gap-1 rounded-full bg-bg1 p-0.5" role="group" aria-label={t("mode.label")}>
      {MODES.map((m) => (
        <Button
          key={m}
          size="sm"
          variant="ghost"
          aria-pressed={mode === m}
          onClick={() => onChange(m)}
          className={cn(
            "h-6 rounded-full px-3 font-mono text-[10px] uppercase tracking-widest",
            mode === m ? "bg-moss text-foreground" : "text-dim",
          )}
        >
          {t(`mode.${m}`)}
        </Button>
      ))}
    </div>
  );
}
