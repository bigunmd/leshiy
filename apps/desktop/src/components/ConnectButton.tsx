import { cn } from "@/lib/utils";
import type { TunnelState } from "@/lib/types";

interface Props { state: TunnelState; onToggle: () => void; disabled?: boolean; }

const CORE: Record<TunnelState, string> = {
  Disconnected: "orb-ember border-2 border-[#3A5240] text-[#6E8C6B] bg-[radial-gradient(circle_at_50%_40%,var(--color-panel)_0%,var(--color-bg0)_75%)]",
  Connecting: "orb-pulse border-2 border-border text-wisp-bright bg-[radial-gradient(circle_at_50%_38%,#7CE07A18_0%,var(--color-bg0)_70%)]",
  Reconnecting: "orb-pulse border-2 border-border text-wisp-bright bg-[radial-gradient(circle_at_50%_38%,#7CE07A18_0%,var(--color-bg0)_70%)]",
  Connected: "orb-breathe border-2 border-wisp text-wisp-bright bg-[radial-gradient(circle_at_50%_38%,#7CE07A30_0%,var(--color-bg0)_70%)]",
  Error: "orb-gutter border-2 border-warn text-warn-bright bg-[radial-gradient(circle_at_50%_38%,#E0954A22_0%,var(--color-bg0)_70%)] shadow-[0_0_22px_#E0954A44]",
};

export function ConnectButton({ state, onToggle, disabled }: Props) {
  const connecting = state === "Connecting" || state === "Reconnecting";
  return (
    <button onClick={onToggle} disabled={disabled} aria-label="toggle connection"
      className={cn("relative grid place-items-center h-[168px] w-[168px]", disabled && "opacity-50")}>
      {connecting && (
        <span className="orb-spin absolute inset-2 rounded-full border-[3px] border-transparent"
          style={{ borderTopColor: "var(--color-wisp)", borderRightColor: "#7CE07A55" }} />
      )}
      <span className={cn("orb-core grid h-36 w-36 place-items-center rounded-full text-[40px] transition-colors duration-300", CORE[state])}>
        ⏻
      </span>
    </button>
  );
}
