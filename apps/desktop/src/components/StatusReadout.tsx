import { useTranslation } from "react-i18next";
import type { Rates, TunnelState } from "@/lib/types";
import { formatBytes, formatSpeed } from "@/lib/format";
import { ArrowDown, ArrowUp } from "./icons";
const COLOR: Record<TunnelState, string> = {
  Disconnected: "text-dim", Connecting: "text-wisp-bright", Connected: "text-wisp-bright", Reconnecting: "text-wisp-bright", Error: "text-warn",
};
export function StatusReadout({ state, rates }: { state: TunnelState; rates: Rates }) {
  const { t } = useTranslation();
  const live = state === "Connected";
  return (
    <div className="flex min-h-16 flex-col items-center gap-3">
      <div className={`font-mono text-[13px] font-medium tracking-wide ${COLOR[state]}`}>{t(`state.${state}`)}</div>
      <div className="flex min-h-4 gap-[18px] font-mono text-xs tabular-nums text-dim">
        {live ? (<><span className="inline-flex items-center gap-1"><ArrowDown className="h-2.5 w-2.5" /> {formatSpeed(rates.down_bps)}</span><span className="inline-flex items-center gap-1"><ArrowUp className="h-2.5 w-2.5" /> {formatSpeed(rates.up_bps)}</span></>)
              : (<span>{state === "Error" ? t("tapToRetry") : t("tapToConnect")}</span>)}
      </div>
      {live && (<div className="font-mono text-[10px] uppercase tracking-widest text-dim/70">{t("total")} <ArrowDown className="inline h-2 w-2" /> {formatBytes(rates.total_down)} · <ArrowUp className="inline h-2 w-2" /> {formatBytes(rates.total_up)}</div>)}
    </div>
  );
}
