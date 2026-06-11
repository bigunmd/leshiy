import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { Mode, Rates, TunnelState } from "@/lib/types";
import { formatBytes, formatSpeed } from "@/lib/format";
import { ArrowDown, ArrowUp, ChevronDown } from "./icons";
import { cn } from "@/lib/utils";

const COLOR: Record<TunnelState, string> = {
  Disconnected: "text-dim", Connecting: "text-wisp-bright", Connected: "text-wisp-bright", Reconnecting: "text-wisp-bright", Error: "text-warn",
};

interface Props { state: TunnelState; rates: Rates; mode: Mode; vpnDns: string; }

export function StatusReadout({ state, rates, mode, vpnDns }: Props) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const live = state === "Connected";
  const vpnLive = live && mode === "vpn";

  const speeds = (
    <div className="flex min-h-4 gap-[18px] font-mono text-xs tabular-nums text-dim">
      <span className="inline-flex items-center gap-1"><ArrowDown className="h-2.5 w-2.5" /> {formatSpeed(rates.down_bps)}</span>
      <span className="inline-flex items-center gap-1"><ArrowUp className="h-2.5 w-2.5" /> {formatSpeed(rates.up_bps)}</span>
    </div>
  );

  return (
    <div className="flex min-h-16 flex-col items-center gap-3">
      {vpnLive ? (
        <div className="flex items-center gap-1.5 font-mono text-[13px] font-medium tracking-wide text-wisp-bright">
          <span aria-hidden="true">●</span> {t("vpnStatus.protected")}
        </div>
      ) : (
        <div className={`font-mono text-[13px] font-medium tracking-wide ${COLOR[state]}`}>{t(`state.${state}`)}</div>
      )}

      {live ? speeds : (
        <div className="flex min-h-4 gap-[18px] font-mono text-xs tabular-nums text-dim">
          <span>{state === "Error" ? t("tapToRetry") : t("tapToConnect")}</span>
        </div>
      )}

      {live && !vpnLive && (
        <div className="font-mono text-[10px] uppercase tracking-widest text-dim/70">{t("total")} <ArrowDown className="inline h-2 w-2" /> {formatBytes(rates.total_down)} · <ArrowUp className="inline h-2 w-2" /> {formatBytes(rates.total_up)}</div>
      )}

      {vpnLive && (
        <div className="flex flex-col items-center gap-2">
          <button
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            className="inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-widest text-moss"
          >
            {t("vpnStatus.details")} <ChevronDown className={cn("h-3 w-3 transition-transform", open && "rotate-180")} />
          </button>
          {open && (
            <dl className="grid grid-cols-[auto_auto] gap-x-4 gap-y-1 rounded-lg bg-bg1 px-4 py-3 font-mono text-[11px] tabular-nums text-dim">
              <dt className="text-dim/70">{t("vpnStatus.ip")}</dt><dd className="text-right text-foreground">10.71.0.2</dd>
              <dt className="text-dim/70">{t("vpnStatus.dns")}</dt><dd className="text-right text-foreground">{vpnDns}</dd>
              <dt className="text-dim/70">{t("vpnStatus.route")}</dt><dd className="text-right text-foreground">{t("vpnStatus.fullTunnel")}</dd>
              <dt className="text-dim/70">{t("vpnStatus.mtu")}</dt><dd className="text-right text-foreground">1400</dd>
            </dl>
          )}
          <div className="font-mono text-[10px] uppercase tracking-widest text-dim/70">{t("total")} <ArrowDown className="inline h-2 w-2" /> {formatBytes(rates.total_down)} · <ArrowUp className="inline h-2 w-2" /> {formatBytes(rates.total_up)}</div>
        </div>
      )}
    </div>
  );
}
