// 镜像结构扫描:识别 uImage / TRX / squashfs / cramfs / gzip / xz / lzma,
// 输出分区布局。所有解析都要容忍截断与损坏,绝不向上抛异常。
import { MAGICS, findMagic, findBeU32, safeU32, safeU16, hex } from '../../shared/magic.js';
import type { Segment, SegmentType } from '../../shared/types.js';
import { gunzip, xzDecompress, lzmaDecompress } from './compression.js';

const UIMAGE_HDR_LEN = 64;
const TRX_HDR_LEN = 28;

/** uImage 架构码(常用子集) */
const UIMAGE_ARCH: Record<number, string> = {
  1: 'Alpha',
  2: 'ARM',
  3: 'I386',
  5: 'MIPS',
  7: 'PowerPC',
  8: 'IBMS390',
  10: 'MIPS64',
  12: 'ARM64',
  22: 'RISC-V',
};

/** uImage 压缩码 */
const UIMAGE_COMP: Record<number, string> = {
  0: 'none',
  1: 'gzip',
  2: 'bzip2',
  3: 'lzma',
  4: 'lzo',
  5: 'lzma(old)',
  6: 'xz',
  7: 'lz4',
  8: 'zstd',
};

const UIMAGE_TYPE: Record<number, string> = {
  1: 'standalone',
  2: 'kernel',
  3: 'ramdisk',
  4: 'multi',
  5: 'firmware',
};

interface ProtoSegment {
  offset: number;
  size: number;
  type: SegmentType;
  label: string;
  details?: Record<string, string | number | boolean>;
  warnings?: string[];
  error?: string;
  children?: Segment[];
  uncompressedSize?: number;
  sizeIsEstimate?: boolean;
  /** 容器段(uImage/TRX):只作概览与 children 载体,不参与扁平去重 */
  isContainer?: boolean;
}

/** 扫描整个镜像,返回有序、不重叠的段列表(含 padding/unknown 填充) */
export function scanImage(buf: Buffer): Segment[] {
  const protos: ProtoSegment[] = [];
  const warnings: string[] = [];

  // 1. 头部容器:uImage / TRX(标记为容器,不与内部分区争布局)
  const containers: ProtoSegment[] = [];
  const uImage = parseUImage(buf);
  if (uImage) {
    uImage.isContainer = true;
    containers.push(uImage);
    void scanInner(buf.subarray(UIMAGE_HDR_LEN, Math.min(buf.length, UIMAGE_HDR_LEN + (uImage.size || 0))), uImage, 1);
  }
  const trx = parseTrx(buf);
  if (trx) {
    trx.isContainer = true;
    containers.push(trx);
  }

  // 2. 文件系统魔数(全镜像扫描)
  for (const off of findMagic(buf, MAGICS.squashfs)) {
    protos.push(makeSquashfsSegment(buf, off, false));
  }
  for (const off of findMagic(buf, MAGICS.squashfsBe)) {
    protos.push(makeSquashfsSegment(buf, off, true));
  }
  for (const off of findBeU32(buf, 0x28cd3d45)) {
    protos.push(makeCramfsSegment(buf, off));
  }

  // 3. 头部裸压缩流(不在已有容器内部的)
  if (!uImage && !trx) {
    const bare = detectBareCompression(buf, 0);
    if (bare) protos.push(bare);
  }

  // TRX 内部各分区单独识别,并挂到 TRX 容器的 children
  if (trx) {
    const offsets = (trx.details?.partOffsets as string)
      ?.split(',')
      .map((s) => parseInt(s, 10))
      .filter((n) => Number.isFinite(n) && n > 0);
    for (const off of offsets ?? []) {
      const inner = detectBareCompression(buf, off) ?? detectFsAt(buf, off);
      if (inner) {
        inner.label = `TRX 分区 @${hex(off)}:${inner.label}`;
        protos.push(inner);
        trx.children = [...(trx.children ?? []), toSegment(inner)];
      }
    }
  }
  // uImage:数据区紧跟 64 字节头,按头部压缩方式识别为压缩段并挂 children
  if (uImage) {
    const dataOff = UIMAGE_HDR_LEN;
    const inner = detectBareCompression(buf, dataOff);
    if (inner) {
      inner.label = `uImage 数据区:${inner.label}`;
      protos.push(inner);
      uImage.children = [...(uImage.children ?? []), toSegment(inner)];
    }
  }
  // 容器内部识别到的段也加入扁平布局(scanInner 已挂 children)
  for (const c of containers) {
    for (const child of c.children ?? []) protos.push(fromSegment(child));
  }

  // 4. 去重(同偏移同类型保留信息更全的)、排序、裁剪重叠(仅内容段)
  const merged = dedupeAndMerge(protos, buf.length);

  // 5. 填充 padding / unknown 空隙
  const filled = fillGaps(merged, buf.length, buf);

  // 6. 容器概览段放在最前,其后是按字节展开的内容段
  return [...containers.map(toSegment), ...filled.map(toSegment)];
}

function toSegment(p: ProtoSegment): Segment {
  return {
    type: p.type,
    offset: p.offset,
    size: p.size,
    sizeIsEstimate: p.sizeIsEstimate,
    label: p.label,
    details: p.details,
    uncompressedSize: p.uncompressedSize,
    children: p.children,
    warnings: p.warnings,
    error: p.error,
  };
}

/** Segment 回转 ProtoSegment(uImage children 回流到扁平布局用) */
function fromSegment(s: Segment): ProtoSegment {
  return {
    type: s.type,
    offset: s.offset,
    size: s.size,
    sizeIsEstimate: s.sizeIsEstimate,
    label: s.label,
    details: s.details,
    uncompressedSize: s.uncompressedSize,
    children: s.children,
    warnings: s.warnings,
    error: s.error,
  };
}

function parseUImage(buf: Buffer): ProtoSegment | null {
  if (buf.length < UIMAGE_HDR_LEN || !buf.subarray(0, 4).equals(MAGICS.uImage)) return null;
  const warnings: string[] = [];
  const size = safeU32(buf, 12, true) ?? 0; // ih_size
  const load = safeU32(buf, 20, true) ?? 0;
  const ep = safeU32(buf, 24, true) ?? 0;
  const comp = buf[30] ?? 0;
  const type = buf[31] ?? 0;
  const arch = buf[29] ?? 0;
    const name = buf.subarray(32, 64).toString('latin1').replace(/[\x00 ]+$/g, '');
  if (UIMAGE_HDR_LEN + size > buf.length) {
    warnings.push(`数据段声明 ${size} 字节,但镜像剩余 ${Math.max(0, buf.length - UIMAGE_HDR_LEN)} 字节,镜像可能被截断`);
  }
  return {
    offset: 0,
    size: Math.min(UIMAGE_HDR_LEN + size, buf.length),
    type: 'uImage',
    label: `uImage 头 (${UIMAGE_ARCH[arch] ?? `arch#${arch}`}, ${UIMAGE_COMP[comp] ?? `comp#${comp}`})`,
    details: {
      镜像名称: name,
      类型: UIMAGE_TYPE[type] ?? `type#${type}`,
      架构: UIMAGE_ARCH[arch] ?? String(arch),
      压缩方式: UIMAGE_COMP[comp] ?? String(comp),
      数据大小: size,
      加载地址: hex(load),
      入口地址: hex(ep),
      partOffsets: '', // 占位,TRX 不用
    },
    warnings,
  };
}

function parseTrx(buf: Buffer): ProtoSegment | null {
  if (buf.length < TRX_HDR_LEN || !buf.subarray(0, 4).equals(MAGICS.trx)) return null;
  const warnings: string[] = [];
  const length = safeU32(buf, 4, true) ?? 0;
  // 0x0c: flags(u16) + version(u16)
  const flags = safeU16(buf, 12, true) ?? 0;
  const version = safeU16(buf, 14, true) ?? 0;
  // 标准 TRX:三个分区偏移在 0x10 / 0x14 / 0x18
  const offsets = [safeU32(buf, 16, true), safeU32(buf, 20, true), safeU32(buf, 24, true)]
    .filter((n): n is number => n != null && n >= TRX_HDR_LEN && n < buf.length);
  if (length > buf.length) warnings.push(`TRX 声明长度 ${length},实际 ${buf.length},镜像可能被截断`);
  return {
    offset: 0,
    size: Math.min(length || buf.length, buf.length),
    type: 'TRX',
    label: `TRX 容器 (v${version},${offsets.length} 个分区)`,
    details: {
      声明长度: length,
      版本: version,
      标志位: flags,
      分区数: offsets.length,
      partOffsets: offsets.join(','),
    },
    warnings,
  };
}

function makeSquashfsSegment(buf: Buffer, off: number, bigEndian: boolean): ProtoSegment {
  const warnings: string[] = [];
  const bytesUsed = Number(safeU32(buf, off + 0x28, bigEndian) ?? 0) + Number(safeU32(buf, off + 0x2c, bigEndian) ?? 0) * 0x100000000;
  const blockSize = safeU32(buf, off + 0x0c, bigEndian) ?? 0;
  const comp = safeU16(buf, off + 0x14, bigEndian) ?? 0;
  const major = safeU16(buf, off + 0x1c, bigEndian) ?? 0;
  const minor = safeU16(buf, off + 0x1e, bigEndian) ?? 0;
  const compName = [, 'zlib', 'lzma', 'lzo', 'xz', 'lz4', 'zstd'][comp] ?? `comp#${comp}`;
  let size = bytesUsed;
  if (size <= 0 || off + size > buf.length) {
    warnings.push(`SquashFS 声明 bytes_used=${bytesUsed},超出镜像边界,按到镜像末尾估算`);
    size = buf.length - off;
  }
  return {
    offset: off,
    size,
    sizeIsEstimate: bytesUsed <= 0 || off + bytesUsed > buf.length,
    type: 'squashfs',
    label: `SquashFS ${major}.${minor} 根文件系统 (${compName},块 ${blockSize})`,
    details: {
      字节序: bigEndian ? '大端' : '小端',
      版本: `${major}.${minor}`,
      压缩: compName,
      bytes_used: bytesUsed,
      块大小: blockSize,
    },
    warnings,
  };
}

function makeCramfsSegment(buf: Buffer, off: number): ProtoSegment {
  const warnings: string[] = [];
  const size = safeU32(buf, off + 4, true) ?? 0;
    const sig = buf.subarray(off + 16, off + 32).toString('latin1').replace(/[\x00 ]+$/g, '');
  let realSize = size;
  if (size <= 0 || off + size > buf.length) {
    warnings.push('CRAMFS 声明尺寸异常或镜像被截断,按到镜像末尾估算');
    realSize = buf.length - off;
  }
  return {
    offset: off,
    size: realSize,
    sizeIsEstimate: size <= 0 || off + size > buf.length,
    type: 'cramfs',
    label: `CRAMFS 根文件系统${sig ? ` (${sig.trim()})` : ''}`,
    details: { 声明大小: size, 签名: sig.trim() },
    warnings,
  };
}

/** 在指定偏移识别压缩流(尝试解压验证) */
function detectBareCompression(buf: Buffer, off: number): ProtoSegment | null {
  if (off >= buf.length) return null;
  const head = buf.subarray(off);
  // gzip
  if (head.length >= 2 && head[0] === 0x1f && head[1] === 0x8b) {
    try {
      const out = gunzip(head);
      return {
        offset: off,
        size: buf.length - off,
        sizeIsEstimate: true,
        type: 'gzip',
        label: `gzip 压缩段 (解压后 ${out.length} 字节)`,
        uncompressedSize: out.length,
      };
    } catch (e) {
      return {
        offset: off,
        size: buf.length - off,
        sizeIsEstimate: true,
        type: 'gzip',
        label: 'gzip 压缩段(解压失败,可能截断)',
        error: (e as Error).message,
      };
    }
  }
  // xz
  if (head.length >= 6 && head.subarray(0, 6).equals(MAGICS.xz)) {
    // xz 是异步的,这里只登记,真正解压在分析阶段;同步给估算段
    return {
      offset: off,
      size: buf.length - off,
      sizeIsEstimate: true,
      type: 'xz',
      label: 'xz 压缩段',
    };
  }
  // lzma alone(5d 00 00 开头)
  if (head.length >= 3 && head[0] === 0x5d && head[1] === 0x00 && head[2] === 0x00) {
    return {
      offset: off,
      size: buf.length - off,
      sizeIsEstimate: true,
      type: 'lzma',
      label: 'LZMA 压缩段',
    };
  }
  return null;
}

function detectFsAt(buf: Buffer, off: number): ProtoSegment | null {
  if (off + 4 > buf.length) return null;
  if (buf.subarray(off, off + 4).equals(MAGICS.squashfs)) return makeSquashfsSegment(buf, off, false);
  if (buf.subarray(off, off + 4).equals(MAGICS.squashfsBe)) return makeSquashfsSegment(buf, off, true);
  if (buf.readUInt32BE(off) === 0x28cd3d45) return makeCramfsSegment(buf, off);
  return null;
}

/** 递归扫描容器内部(目前处理 uImage 数据区) */
function scanInner(region: Buffer, parent: ProtoSegment, depth: number): void {
  if (depth > 2 || region.length < 4) return;
  const children: Segment[] = [];
  // uImage 数据区按头部 comp 尝试解压,再在解压产物里找文件系统
  const compName = String(parent.details?.压缩方式 ?? '');
  const baseOff = parent.offset + UIMAGE_HDR_LEN;
  let working: Buffer = region;
  try {
    if (compName === 'gzip') working = gunzip(region);
    else if (compName === 'xz') {
      // 同步场景无法 await,登记占位;真正解压由 analyzer 做
      children.push({ type: 'xz', offset: baseOff, size: region.length, sizeIsEstimate: true, label: 'uImage 内 xz 内核数据' });
      parent.children = children;
      return;
    } else if (compName === 'lzma' || compName === 'lzma(old)') {
      children.push({ type: 'lzma', offset: baseOff, size: region.length, sizeIsEstimate: true, label: 'uImage 内 LZMA 内核数据' });
      parent.children = children;
      return;
    }
  } catch (e) {
    parent.warnings = [...(parent.warnings ?? []), `uImage 数据解压失败:${(e as Error).message}`];
    return;
  }
  for (const off of findMagic(working, MAGICS.squashfs)) {
    const seg = makeSquashfsSegment(working, off, false);
    seg.offset += baseOff;
    children.push(toSegment(seg));
  }
  for (const off of findMagic(working, MAGICS.cramfs)) {
    const seg = makeCramfsSegment(working, off);
    seg.offset += baseOff;
    children.push(toSegment(seg));
  }
  if (children.length) parent.children = children;
}

function dedupeAndMerge(protos: ProtoSegment[], imageLen: number): ProtoSegment[] {
  const sorted = [...protos].sort((a, b) => a.offset - b.offset || b.size - a.size);
  const out: ProtoSegment[] = [];
  for (const p0 of sorted) {
    let p = p0;
    const last = out[out.length - 1];
    if (last && p.offset < last.offset + Math.min(last.size, imageLen)) {
      if (p.type === last.type) continue;
      const pIsFs = p.type === 'squashfs' || p.type === 'cramfs';
      const lastIsEstimate = last.sizeIsEstimate === true;
      // 精确文件系统段优先于估算的压缩段:压缩段收缩到文件系统之前
      if (pIsFs && lastIsEstimate) {
        const newSize = p.offset - last.offset;
        if (newSize > 0) {
          out[out.length - 1] = { ...last, size: newSize };
        } else {
          out.pop();
        }
        out.push(p);
        continue;
      }
      // 被完全包含:若是文件系统/压缩段且上一段是估算段,同样需要保留(上面已处理);其余跳过
      if (p.offset >= last.offset && p.offset + p.size <= last.offset + last.size) continue;
      // 部分重叠:裁剪起点
      p = { ...p, offset: last.offset + last.size, size: p.size - (last.offset + last.size - p.offset) };
      if (p.size <= 0) continue;
    }
    out.push(p);
  }
  return out;
}

function fillGaps(segs: ProtoSegment[], imageLen: number, buf: Buffer): ProtoSegment[] {
  const out: ProtoSegment[] = [];
  let cursor = 0;
  for (const s of segs) {
    if (s.offset > cursor) {
      const gap = s.offset - cursor;
      out.push({
        offset: cursor,
        size: gap,
        type: isLikelyPadding(buf.subarray(cursor, s.offset)) ? 'padding' : 'unknown',
        label: gap < 64 ? '间隔/填充区' : '未识别数据区',
      });
    }
    cursor = s.offset + s.size;
    out.push(s);
  }
  if (cursor < imageLen) {
    out.push({
      offset: cursor,
      size: imageLen - cursor,
      type: isLikelyPadding(buf.subarray(cursor, imageLen)) ? 'padding' : 'unknown',
      label: '尾部填充区',
    });
  }
  return out;
}

/** 填充区判定:全 0x00 或全 0xFF 视为 padding */
function isLikelyPadding(b: Buffer): boolean {
  if (b.length === 0) return true;
  let zeros = 0;
  let ffs = 0;
  for (const v of b) {
    if (v === 0x00) zeros++;
    else if (v === 0xff) ffs++;
    else return false;
  }
  return zeros === b.length || ffs === b.length;
}

/** 分析阶段调用:尝试解压所有压缩段,把结果挂到 segment 上并返回解压数据映射 */
export async function decompressSegments(
  buf: Buffer,
  segments: Segment[]
): Promise<Map<string, Buffer>> {
  const results = new Map<string, Buffer>();
  const walk = async (segs: Segment[], prefix: string) => {
    for (let i = 0; i < segs.length; i++) {
      const s = segs[i];
      const key = `${prefix}/${i}`;
      const region = buf.subarray(s.offset, Math.min(buf.length, s.offset + s.size));
      try {
        if (s.type === 'gzip') {
          const out = gunzip(region);
          results.set(key, out);
          s.uncompressedSize = out.length;
        } else if (s.type === 'xz') {
          const out = await xzDecompress(region);
          results.set(key, out);
          s.uncompressedSize = out.length;
        } else if (s.type === 'lzma') {
          const out = await lzmaDecompress(region);
          results.set(key, out);
          s.uncompressedSize = out.length;
        }
      } catch (e) {
        s.error = (e as Error).message;
        s.warnings = [...(s.warnings ?? []), '解压失败,段内容不可用(不影响其它部分分析)'];
      }
      if (s.children) await walk(s.children, `${key}/c`);
    }
  };
  await walk(segments, 'seg');
  return results;
}
