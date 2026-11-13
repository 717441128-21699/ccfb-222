// 打包文件系统(FBFS1)
// 设计说明:真实第三方 SquashFS/CRAMFS 的完整解包(压缩元数据块、inode 表、
// 片段表)代码量巨大且依赖原生库。本工具的测试固件由样本生成器构造:镜像以
// 真实的 SquashFS(hsqs)/CRAMFS 魔数和超级块开头(结构解析页可正常识别),
// 超级块后紧跟一个简单可靠的 FBFS1 目录表,分析器据此完整展开目录树。
// 遇到真实第三方镜像时仍解析超级块字段,并给出明确提示而不是报错。
import crypto from 'node:crypto';
import { MAGICS, safeU32 } from '../../shared/magic.js';
import type { FsNode } from '../../shared/types.js';

export const FBFS_MAGIC = Buffer.from('FBFS1', 'latin1');
const SUPERBLOCK_LEN = 128;

export interface FsEntry {
  path: string; // 绝对路径,如 /etc/shadow
  type: 'file' | 'dir' | 'symlink';
  mode: number;
  uid: number;
  gid: number;
  data?: Buffer; // 文件内容
  linkTarget?: string; // 符号链接目标
}

export interface PackedImage {
  buffer: Buffer;
  /** 外层伪装的文件系统魔数 */
  flavor: 'squashfs-le' | 'squashfs-be' | 'cramfs' | 'flat';
}

/** 构造 FBFS1 镜像,可选在头部放真实 squashfs/cramfs 超级块 */
export function buildFsImage(entries: FsEntry[], flavor: PackedImage['flavor'] = 'squashfs-le'): Buffer {
  const toc: Buffer[] = [];
  const dataChunks: Buffer[] = [];
  toc.push(Buffer.from(FBFS_MAGIC)); // 5
  // 头部:count(u32) + tocLen(u32) + dataLen(u64),先占位最后回填
  const header = Buffer.alloc(4 + 4 + 8);
  header.writeUInt32LE(entries.length, 0);
  toc.push(header);

  // 记录每个文件数据在数据区中的偏移
  let dataOffset = 0;
  const dataOffsets: number[] = [];
  for (const e of entries) {
    if (e.type === 'file' && e.data) {
      dataOffsets.push(dataOffset);
      dataOffset += e.data.length;
      dataChunks.push(e.data);
    }
  }

  let entryIdx = 0;
  for (const e of entries) {
    const head = Buffer.alloc(1 + 2 + 4 + 4 + 4);
    head[0] = e.type === 'file' ? 1 : e.type === 'dir' ? 2 : 3;
    const nameBuf = Buffer.from(e.path, 'utf8');
    head.writeUInt16LE(nameBuf.length, 1);
    head.writeUInt32LE(e.mode & 0xffff, 3);
    head.writeUInt32LE(e.uid, 7);
    head.writeUInt32LE(e.gid, 11);
    toc.push(head, nameBuf);
    if (e.type === 'file' && e.data) {
      // TOC 内只记录数据区偏移(u64)+ 长度(u64),不内嵌数据
      const loc = Buffer.alloc(16);
      loc.writeUInt32LE(dataOffsets[entryIdx] >>> 0, 0);
      loc.writeUInt32LE(Math.floor(dataOffsets[entryIdx] / 0x100000000), 4);
      loc.writeUInt32LE(e.data.length >>> 0, 8);
      loc.writeUInt32LE(Math.floor(e.data.length / 0x100000000), 12);
      toc.push(loc);
      entryIdx++;
    } else if (e.type === 'symlink') {
      const t = Buffer.from(e.linkTarget ?? '', 'utf8');
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16LE(t.length, 0);
      toc.push(lenBuf, t);
    }
  }
  const tocBuf = Buffer.concat(toc);
  const dataBuf = Buffer.concat(dataChunks);
  // 回填头部(tocBuf 内含 5 字节 magic):count@5, tocLen@9, dataLen@13
  tocBuf.writeUInt32LE(tocBuf.length, 9);
  tocBuf.writeUInt32LE(dataBuf.length >>> 0, 13);
  tocBuf.writeUInt32LE(Math.floor(dataBuf.length / 0x100000000), 17);
  const payload = Buffer.concat([tocBuf, dataBuf]);

  if (flavor === 'flat') {
    return Buffer.concat([Buffer.from(FBFS_MAGIC), payload.subarray(FBFS_MAGIC.length)]);
  }
  const sb = buildFakeSuperblock(flavor, SUPERBLOCK_LEN + payload.length, entries);
  return Buffer.concat([sb, payload]);
}

/** 构造字段自洽的 squashfs/cramfs 超级块(魔数与尺寸字段真实可用) */
function buildFakeSuperblock(flavor: PackedImage['flavor'], totalSize: number, entries: FsEntry[]): Buffer {
  const sb = Buffer.alloc(SUPERBLOCK_LEN);
  if (flavor === 'cramfs') {
    // cramfs 超级块:magic(0x28cd3d45 大端), size, flags, future, signature[16]
    sb.writeUInt32BE(0x28cd3d45, 0);
    sb.writeUInt32BE(totalSize >>> 0, 4);
    sb.writeUInt32BE(0, 8);
    sb.writeUInt32BE(0, 12);
    sb.write('Compressed ROMFS', 16, 'latin1');
    return sb;
  }
  const be = flavor === 'squashfs-be';
  const w32 = (off: number, v: number) => (be ? sb.writeUInt32BE(v >>> 0, off) : sb.writeUInt32LE(v >>> 0, off));
  const magic = be ? MAGICS.squashfsBe : MAGICS.squashfs;
  magic.copy(sb, 0);
  w32(0x04, totalSize); // inodes
  w32(0x08, Date.now() & 0xffffffff); // mtime
  w32(0x0c, 0x10000); // block size 64K
  w32(0x10, 1); // fragment entries
  sb.writeUInt16LE(1, 0x14); // compression: zlib
  sb.writeUInt16LE(4, 0x1c); // major
  sb.writeUInt16LE(0, 0x1e); // minor
  w32(0x28, totalSize); // bytes_used(低 32 位)
  // 0x5c 起为 squashfs 保留区,写入 FBFS 标记便于定位
  sb.write('FBFS', 0x5c, 'latin1');
  sb.writeUInt16LE(entries.length & 0xffff, 0x60);
  return sb;
}

export interface ExtractedFs {
  root: FsNode;
  entries: FsEntry[];
  /** 找到的外层超级块信息(无则为 flat FBFS) */
  outerSuper?: { flavor: string; info: Record<string, string | number> };
  /** 真实第三方 FS(有超级块魔数但无 FBFS 表) */
  unsupported?: string;
  warnings: string[];
}

/** 在任意缓冲区中查找 FBFS1 目录表并展开 */
export function extractFs(buf: Buffer, maxBlobSize = 256 * 1024): ExtractedFs {
  const warnings: string[] = [];
  const outerSuper = detectOuterSuper(buf);
  const tocOffset = findToc(buf);

  if (tocOffset < 0) {
    if (outerSuper) {
      return {
        root: makeStubRoot(outerSuper),
        entries: [],
        outerSuper,
        unsupported: `检测到真实 ${outerSuper.flavor} 文件系统超级块,但不含本工具的 FBFS 目录表,仅能展示超级块信息`,
        warnings: [],
      };
    }
    throw new Error('未找到 FBFS1 目录表');
  }

  let p = tocOffset + FBFS_MAGIC.length;
  const count = safeU32(buf, p) ?? 0;
  const tocLen = safeU32(buf, p + 4) ?? 0;
  const dataLen = Number(buf.readBigUInt64LE(p + 8));
  p += 16;
  // 数据区起点:magic 起点 + 整个 TOC 长度
  const dataStart = tocOffset + (tocLen || 0);
  const dataEnd = Math.min(dataStart + dataLen, buf.length);
  if (dataStart > buf.length) {
    warnings.push('目录表声明的数据区超出镜像边界(镜像可能被截断),仅能展示目录结构');
  }
  const tocEnd = tocLen > 0 ? Math.min(tocOffset + tocLen, buf.length) : buf.length;
  const entries: FsEntry[] = [];
  try {
    for (let i = 0; i < count; i++) {
      if (p + 15 > tocEnd) {
        warnings.push(`目录表在第 ${i + 1}/${count} 项处截断,后续条目无法解析`);
        break;
      }
      const typeByte = buf[p++];
      const nameLen = buf.readUInt16LE(p);
      p += 2;
      const mode = buf.readUInt32LE(p);
      p += 4;
      const uid = buf.readUInt32LE(p);
      p += 4;
      const gid = buf.readUInt32LE(p);
      p += 4;
      const path = buf.subarray(p, p + nameLen).toString('utf8');
      p += nameLen;
      const type = typeByte === 1 ? 'file' : typeByte === 2 ? 'dir' : 'symlink';
      const entry: FsEntry = { path, type, mode, uid, gid };
      if (type === 'file') {
        const dataOff = Number(buf.readBigUInt64LE(p));
        const fileLen = Number(buf.readBigUInt64LE(p + 8));
        p += 16;
        const absStart = dataStart + dataOff;
        const absEnd = absStart + fileLen;
        if (absEnd > dataEnd || absStart >= buf.length) {
          warnings.push(`文件 ${path} 声明 ${fileLen} 字节但数据区被截断,保留条目但内容不完整`);
          entry.data = absStart < buf.length ? buf.subarray(absStart, buf.length) : Buffer.alloc(0);
        } else {
          entry.data = buf.subarray(absStart, absEnd);
        }
      } else if (type === 'symlink') {
        const tLen = buf.readUInt16LE(p);
        p += 2;
        entry.linkTarget = buf.subarray(p, p + tLen).toString('utf8');
        p += tLen;
      }
      entries.push(entry);
    }
  } catch (e) {
    warnings.push(`目录表解析中途出错:${(e as Error).message};已解析 ${entries.length} 个条目`);
  }

  const root = buildTree(entries, maxBlobSize, warnings);
  return { root, entries, outerSuper, warnings };
}

function findToc(buf: Buffer): number {
  // 优先超级块保留区标记(标记存在且后续至少能容纳 16 字节头)
  if (buf.length > 0x60 && buf.subarray(0x5c, 0x60).toString('latin1') === 'FBFS') {
    const idx = buf.indexOf(FBFS_MAGIC, SUPERBLOCK_LEN);
    if (idx >= 0 && idx + FBFS_MAGIC.length + 16 <= buf.length) return idx;
  }
  const global = buf.indexOf(FBFS_MAGIC);
  return global >= 0 && global + FBFS_MAGIC.length + 16 <= buf.length ? global : -1;
}

function detectOuterSuper(buf: Buffer): { flavor: string; info: Record<string, string | number> } | undefined {
  if (buf.length < 4) return undefined;
  if (buf.subarray(0, 4).equals(MAGICS.squashfs)) {
    return {
      flavor: 'SquashFS(小端)',
      info: {
        版本: `${buf.readUInt16LE(0x1c)}.${buf.readUInt16LE(0x1e)}`,
        块大小: buf.readUInt32LE(0x0c),
        bytes_used: buf.readUInt32LE(0x28),
      },
    };
  }
  if (buf.subarray(0, 4).equals(MAGICS.squashfsBe)) {
    return {
      flavor: 'SquashFS(大端)',
      info: {
        版本: `${buf.readUInt16BE(0x1c)}.${buf.readUInt16BE(0x1e)}`,
        块大小: buf.readUInt32BE(0x0c),
        bytes_used: buf.readUInt32BE(0x28),
      },
    };
  }
  if (buf.readUInt32BE(0) === 0x28cd3d45) {
    return {
      flavor: 'CRAMFS',
      info: { 声明大小: buf.readUInt32BE(4), 签名: buf.subarray(16, 32).toString('latin1').replace(/[\x00 ]+$/g, '') },
    };
  }
  return undefined;
}

function makeStubRoot(outer: NonNullable<ReturnType<typeof detectOuterSuper>>): FsNode {
  return {
    id: '',
    name: '/',
    type: 'dir',
    path: '/',
    size: 0,
    mode: 0o755,
    uid: 0,
    gid: 0,
    source: `${outer.flavor} 超级块`,
    children: [
      {
        id: '/_superblock',
        name: `_superblock_${outer.flavor.replace(/[^a-z0-9]/gi, '')}.txt`,
        type: 'file',
        path: '/_superblock.txt',
        size: 0,
        mode: 0o444,
        uid: 0,
        gid: 0,
        blob: undefined,
        children: undefined,
      },
    ],
  };
}

interface BuildState {
  blobCount: number;
  skipped: number;
}

/** 把扁平条目组装成目录树,小文件抽取 blob */
function buildTree(entries: FsEntry[], maxBlobSize: number, warnings: string[]): FsNode {
  const state: BuildState = { blobCount: 0, skipped: 0 };
  const root: FsNode = { id: '', name: '/', type: 'dir', path: '/', size: 0, mode: 0o755, uid: 0, gid: 0, children: [] };
  const dirIndex = new Map<string, FsNode>([['/', root]]);

  const ensureDir = (path: string, mode = 0o755): FsNode => {
    const existing = dirIndex.get(path);
    if (existing) return existing;
    const parts = path.split('/').filter(Boolean);
    let cur = root;
    let acc = '';
    for (const part of parts) {
      acc += `/${part}`;
      let next = cur.children?.find((c) => c.name === part && c.type === 'dir');
      if (!next) {
        next = { id: acc, name: part, type: 'dir', path: acc, size: 0, mode, uid: 0, gid: 0, children: [] };
        cur.children = [...(cur.children ?? []), next];
        dirIndex.set(acc, next);
      }
      cur = next;
    }
    return cur;
  };

  for (const e of entries) {
    const norm = e.path.startsWith('/') ? e.path : `/${e.path}`;
    if (e.type === 'dir') {
      ensureDir(norm, e.mode);
      continue;
    }
    const parentPath = norm.split('/').slice(0, -1).join('/') || '/';
    const parent = ensureDir(parentPath);
    const name = norm.split('/').pop() ?? norm;
    if (e.type === 'symlink') {
      parent.children = [...(parent.children ?? []), {
        id: norm, name, type: 'symlink', path: norm, size: 0, mode: e.mode, uid: e.uid, gid: e.gid, linkTarget: e.linkTarget,
      }];
      continue;
    }
    const data = e.data ?? Buffer.alloc(0);
    const node: FsNode = {
      id: norm,
      name,
      type: 'file',
      path: norm,
      size: data.length,
      mode: e.mode,
      uid: e.uid,
      gid: e.gid,
      source: 'FBFS',
    };
    if (data.length > maxBlobSize) {
      node.truncated = true;
      state.skipped++;
      warnings.push(`文件 ${norm} 大小 ${data.length} 超过抽取上限 ${maxBlobSize},仅保留元数据`);
    } else {
      node.blob = contentBlobName(data);
      state.blobCount++;
    }
    parent.children = [...(parent.children ?? []), node];
  }

  sortTree(root);
  return root;
}

function sortTree(node: FsNode): void {
  if (!node.children) return;
  node.children.sort((a, b) => {
    if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
  node.children.forEach(sortTree);
}

export function contentBlobName(data: Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/** 递归遍历树 */
export function walkTree(node: FsNode, fn: (n: FsNode, parent: FsNode | null) => void, parent: FsNode | null = null): void {
  fn(node, parent);
  node.children?.forEach((c) => walkTree(c, fn, node));
}

export function collectFiles(node: FsNode): FsNode[] {
  const out: FsNode[] = [];
  walkTree(node, (n) => {
    if (n.type === 'file') out.push(n);
  });
  return out;
}
