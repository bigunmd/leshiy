import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Profile } from "@/lib/types";
export function useProfiles() {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const refresh = useCallback(async () => {
    const [list, active] = await Promise.all([api.listProfiles(), api.activeProfile()]);
    setProfiles(list); setActiveId(active?.id ?? null);
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);
  return {
    profiles, activeId,
    active: profiles.find((p) => p.id === activeId) ?? null,
    refresh,
    importProfile: async (uri: string, name: string) => { const id = await api.importProfile(uri, name); await api.setActive(id); await refresh(); },
    remove: async (id: string) => { await api.removeProfile(id); await refresh(); },
    rename: async (id: string, name: string) => { await api.renameProfile(id, name); await refresh(); },
    select: async (id: string) => { await api.setActive(id); await refresh(); },
  };
}
