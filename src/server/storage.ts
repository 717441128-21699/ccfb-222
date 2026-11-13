// 本地存储:所有数据只落在工作区 data/ 下,不离开本机
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type { FirmwareMeta } from '../shared/types.js';

export const DATA_DIR = path.resolve(process.cwd(), 'data');
const LIB_DIR = path.join(DATA_DIR, 'library');
const BLOB_DIR = path.join(DATA_DIR, 'blobs');
const INDEX_FILE = path.join(DATA_DIR, 'index.json');

export function ensureStorage(): void {
  fs.mkdirSync(LIB_DIR, { recursive: true });
  fs.mkdirSync(BLOB_DIR, { recursive: true });
  if (!fs.existsSync(INDEX_FILE)) fs.writeFileSync(INDEX_FILE, '[]', 'utf8');
}

export function sha256(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

export function firmwarePath(id: string): string {
  return path.join(LIB_DIR, `${id}.bin`);
}

export function blobPath(hash: string): string {
  return path.join(BLOB_DIR, hash);
}

export function saveBlob(data: Buffer): string {
  const hash = sha256(data);
  const p = blobPath(hash);
  if (!fs.existsSync(p)) fs.writeFileSync(p, data);
  return hash;
}

export function readBlob(hash: string): Buffer | null {
  const p = blobPath(hash);
  if (!fs.existsSync(p)) return null;
  return fs.readFileSync(p);
}

export function loadIndex(): FirmwareMeta[] {
  try {
    return JSON.parse(fs.readFileSync(INDEX_FILE, 'utf8')) as FirmwareMeta[];
  } catch {
    return [];
  }
}

export function saveIndex(list: FirmwareMeta[]): void {
  fs.writeFileSync(INDEX_FILE, JSON.stringify(list, null, 2), 'utf8');
}

export function upsertMeta(meta: FirmwareMeta): void {
  const list = loadIndex();
  const i = list.findIndex((m) => m.id === meta.id);
  if (i >= 0) list[i] = meta;
  else list.push(meta);
  saveIndex(list);
}

export function getMeta(id: string): FirmwareMeta | null {
  return loadIndex().find((m) => m.id === id) ?? null;
}

export function deleteFirmware(id: string): boolean {
  const list = loadIndex();
  const next = list.filter((m) => m.id !== id);
  if (next.length === list.length) return false;
  saveIndex(next);
  const fp = firmwarePath(id);
  if (fs.existsSync(fp)) fs.rmSync(fp);
  return true;
}
