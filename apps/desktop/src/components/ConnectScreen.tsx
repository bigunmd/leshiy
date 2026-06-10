import { motion } from "motion/react";
import { useTranslation } from "react-i18next";
import type { Profile, Rates, TunnelState } from "@/lib/types";
import { ConnectButton } from "./ConnectButton";
import { StatusReadout } from "./StatusReadout";
import { ConfigChip } from "./ConfigChip";
import { TopBar } from "./TopBar";

interface Props {
  state: TunnelState; rates: Rates; active: Profile | null;
  onToggle: () => void; onOpenConfigs: () => void; onOpenSettings: () => void; onOpenLanguage: () => void;
}
export function ConnectScreen(p: Props) {
  const { t } = useTranslation();
  const reveal = (delay: number) => ({ initial: { opacity: 0, y: 12 }, animate: { opacity: 1, y: 0 }, transition: { delay, duration: 0.5, ease: "easeOut" as const } });
  return (
    <div className="relative z-10 flex h-full flex-col">
      <motion.div {...reveal(0.05)}><TopBar onLanguage={p.onOpenLanguage} onSettings={p.onOpenSettings} /></motion.div>
      <main className="flex flex-1 flex-col items-center justify-center gap-[26px]">
        <motion.div {...reveal(0.18)}><ConnectButton state={p.state} onToggle={p.onToggle} disabled={!p.active} /></motion.div>
        <motion.div {...reveal(0.3)}><StatusReadout state={p.state} rates={p.rates} /></motion.div>
        <motion.div {...reveal(0.42)} className="flex flex-col items-center gap-2.5">
          <ConfigChip active={p.active} onClick={p.onOpenConfigs} />
          <button onClick={p.onOpenConfigs} className="font-mono text-[10px] uppercase tracking-widest text-moss">{t("manageConfigs")} ›</button>
        </motion.div>
      </main>
    </div>
  );
}
