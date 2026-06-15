import { cn } from "@/lib/utils";
import type { TunnelState } from "@/lib/types";
import { PowerIcon } from "./icons";

interface Props { state: TunnelState; onToggle: () => void; disabled?: boolean; }

const CORE: Record<TunnelState, string> = {
  Disconnected: "orb-ember border-2 border-[#3A5240] text-[#6E8C6B] bg-[radial-gradient(circle_at_50%_40%,var(--color-panel)_0%,var(--color-bg0)_75%)]",
  Connecting: "orb-pulse border-2 border-border text-wisp-bright bg-[radial-gradient(circle_at_50%_38%,#7CE07A18_0%,var(--color-bg0)_70%)]",
  Reconnecting: "orb-pulse border-2 border-border text-wisp-bright bg-[radial-gradient(circle_at_50%_38%,#7CE07A18_0%,var(--color-bg0)_70%)]",
  Disconnecting: "orb-pulse border-2 border-border text-dim bg-[radial-gradient(circle_at_50%_38%,#6E8C6B18_0%,var(--color-bg0)_70%)]",
  Connected: "orb-breathe border-2 border-wisp text-wisp-bright bg-[radial-gradient(circle_at_50%_38%,#7CE07A30_0%,var(--color-bg0)_70%)]",
  Error: "orb-gutter border-2 border-warn text-warn-bright bg-[radial-gradient(circle_at_50%_38%,#E0954A22_0%,var(--color-bg0)_70%)] shadow-[0_0_22px_#E0954A44]",
};

export function ConnectButton({ state, onToggle, disabled }: Props) {
  // Spinner for every in-flight transition, including teardown.
  const busy = state === "Connecting" || state === "Reconnecting" || state === "Disconnecting";
  // Block the click during teardown so it can't interrupt the route/DNS restore.
  const blocked = disabled || state === "Disconnecting";
  return (
    <button onClick={onToggle} disabled={blocked} aria-label="toggle connection" aria-busy={busy}
      className={cn(
        "group relative grid h-[168px] w-[168px] place-items-center transition-transform duration-100 ease-out",
        // Tactile press: the whole orb dips on press and springs back on release.
        !blocked && "cursor-pointer active:scale-90",
        blocked && "opacity-50",
      )}>
      {busy && (
        <span className="orb-spin absolute inset-2 rounded-full border-[3px] border-transparent"
          style={{ borderTopColor: "var(--color-wisp)", borderRightColor: "#7CE07A55" }} />
      )}
      <span className={cn(
        "orb-core grid h-36 w-36 place-items-center rounded-full transition-[transform,colors,box-shadow] duration-300",
        // Press feedback on the core itself: a quick extra dip + brighten while held.
        !blocked && "group-active:scale-95 group-active:brightness-125 group-active:duration-75",
        CORE[state],
      )}>
        <PowerIcon className="h-12 w-12" />
      </span>
    </button>
  );
}
