import { useEffect, useState } from "react";
import { onState, onStats } from "@/lib/api";
import type { Rates, TunnelState } from "@/lib/types";
const ZERO: Rates = { up_bps: 0, down_bps: 0, total_up: 0, total_down: 0 };
export function useTunnel() {
  const [state, setState] = useState<TunnelState>("Disconnected");
  const [rates, setRates] = useState<Rates>(ZERO);
  useEffect(() => {
    const uns = [onState(setState), onStats(setRates)];
    return () => { uns.forEach((p) => p.then((un) => un())); };
  }, []);
  return { state, rates };
}
