// 两个固件版本的差异对比:文件增删改 + 风险项变化
import type { DiffEntry, DiffResult, FirmwareMeta, FsNode, Finding } from '../../shared/types.js';
import { walkTree } from './packed-fs.js';

interface FileRow {
  path: string;
  size: number;
  blob?: string;
  node: FsNode;
}

function indexFiles(meta: FirmwareMeta): Map<string, FileRow> {
  const map = new Map<string, FileRow>();
  if (meta.analysis?.tree) {
    walkTree(meta.analysis.tree, (n) => {
      if (n.type === 'file') map.set(n.path, { path: n.path, size: n.size, blob: n.blob, node: n });
    });
  }
  return map;
}

export function diffFirmware(a: FirmwareMeta, b: FirmwareMeta): DiffResult {
  const fa = indexFiles(a);
  const fb = indexFiles(b);
  const entries: DiffEntry[] = [];

  for (const [path, row] of fa) {
    const other = fb.get(path);
    if (!other) {
      entries.push({ path, change: 'removed', detail: `旧版本文件,大小 ${row.size}` });
    } else if (row.blob && other.blob && row.blob !== other.blob) {
      entries.push({ path, change: 'modified', detail: `内容变化(${row.size} B → ${other.size} B)` });
    } else if (!row.blob || !other.blob) {
      if (row.size !== other.size) {
        entries.push({ path, change: 'modified', detail: `大小变化(${row.size} B → ${other.size} B)` });
      }
    }
  }
  for (const [path, row] of fb) {
    if (!fa.has(path)) entries.push({ path, change: 'added', detail: `新版本新增,大小 ${row.size}` });
  }
  entries.sort((x, y) => x.path.localeCompare(y.path));

  const keyOf = (f: Finding) => `${f.category}|${f.title}|${f.path ?? ''}`;
  const bKeys = new Set((b.analysis?.findings ?? []).map(keyOf));
  const aKeys = new Set((a.analysis?.findings ?? []).map(keyOf));
  const findingsOnlyInA = (a.analysis?.findings ?? []).filter((f) => !bKeys.has(keyOf(f)));
  const findingsOnlyInB = (b.analysis?.findings ?? []).filter((f) => !aKeys.has(keyOf(f)));

  return {
    aId: a.id,
    bId: b.id,
    aName: a.originalName,
    bName: b.originalName,
    entries,
    findingsOnlyInA,
    findingsOnlyInB,
  };
}
