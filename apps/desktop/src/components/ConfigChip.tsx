import { useTranslation } from "react-i18next";
import type { Profile } from "@/lib/types";
export function ConfigChip({ active, onClick }: { active: Profile | null; onClick: () => void }) {
  const { t } = useTranslation();
  return (
    <button onClick={onClick}
      className="inline-flex items-center gap-2 rounded-full border border-border bg-panel px-3.5 py-2 text-xs text-[#C7D9C2]">
      <span aria-hidden>🌲</span>
      <span className={active ? "" : "text-dim"}>{active ? active.name : t("noConfig")}</span>
      <span className="text-moss">▾</span>
    </button>
  );
}
