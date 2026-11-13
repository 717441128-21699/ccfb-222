import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import type { FirmwareMeta } from '../shared/types';
import { api } from './api';

interface Store {
  items: FirmwareMeta[];
  selectedId: string | null;
  select: (id: string | null) => void;
  refresh: () => Promise<void>;
  loading: boolean;
  error: string | null;
}

const Ctx = createContext<Store | null>(null);
const STORAGE_KEY = 'fb-selected-id';

export function FirmwareProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<FirmwareMeta[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(() => localStorage.getItem(STORAGE_KEY));
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const list = await api.list();
      setItems(list);
      setError(null);
      if (selectedId && !list.some((m) => m.id === selectedId)) {
        setSelectedId(null);
        localStorage.removeItem(STORAGE_KEY);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const select = (id: string | null) => {
    setSelectedId(id);
    if (id) localStorage.setItem(STORAGE_KEY, id);
    else localStorage.removeItem(STORAGE_KEY);
  };

  return (
    <Ctx.Provider value={{ items, selectedId, select, refresh, loading, error }}>
      {children}
    </Ctx.Provider>
  );
}

export function useFirmware(): Store {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useFirmware 必须在 FirmwareProvider 内使用');
  return ctx;
}

/** 拉取选中固件的完整数据(列表接口不含 analysis) */
export function useSelectedFull(): { meta: FirmwareMeta | null; loading: boolean; reload: () => Promise<void> } {
  const { items, selectedId } = useFirmware();
  const [meta, setMeta] = useState<FirmwareMeta | null>(null);
  const [loading, setLoading] = useState(false);

  const reload = async () => {
    if (!selectedId) {
      setMeta(null);
      return;
    }
    setLoading(true);
    try {
      setMeta(await api.get(selectedId));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId, items.length]);

  const stub = selectedId ? items.find((m) => m.id === selectedId) ?? null : null;
  return { meta: meta ?? stub, loading, reload };
}
