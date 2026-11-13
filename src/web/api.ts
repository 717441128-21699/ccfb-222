import type { DiffResult, FirmwareMeta } from '../shared/types';

async function jsonOrThrow<T>(r: Response): Promise<T> {
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try {
      const body = await r.json();
      msg = body.error || msg;
    } catch {
      /* ignore */
    }
    throw new Error(msg);
  }
  return r.json() as Promise<T>;
}

export const api = {
  async list(): Promise<FirmwareMeta[]> {
    return jsonOrThrow(await fetch('/api/firmware'));
  },
  async get(id: string): Promise<FirmwareMeta> {
    return jsonOrThrow(await fetch(`/api/firmware/${id}`));
  },
  async upload(file: File, note?: string, extraWords?: string[]): Promise<FirmwareMeta> {
    const fd = new FormData();
    fd.append('firmware', file);
    if (note) fd.append('note', note);
    if (extraWords?.length) fd.append('extraWords', JSON.stringify(extraWords));
    return jsonOrThrow(await fetch('/api/firmware', { method: 'POST', body: fd }));
  },
  async reanalyze(id: string, extraWords: string[]): Promise<FirmwareMeta> {
    return jsonOrThrow(
      await fetch(`/api/firmware/${id}/reanalyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ extraWords }),
      })
    );
  },
  async remove(id: string): Promise<{ ok: boolean }> {
    return jsonOrThrow(await fetch(`/api/firmware/${id}`, { method: 'DELETE' }));
  },
  async raw(id: string, blob: string): Promise<{ size: number; isText: boolean; text: string | null; hex: { offset: string; hex: string; ascii: string }[] }> {
    return jsonOrThrow(await fetch(`/api/firmware/${id}/raw?blob=${encodeURIComponent(blob)}`));
  },
  reportUrl(id: string): string {
    return `/api/firmware/${id}/report`;
  },
  async diff(a: string, b: string): Promise<DiffResult> {
    return jsonOrThrow(await fetch(`/api/diff?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`));
  },
  async importSamples(): Promise<{ imported: Array<{ id: string; name: string; fatalError?: string }> }> {
    return jsonOrThrow(await fetch('/api/samples/import', { method: 'POST' }));
  },
};
