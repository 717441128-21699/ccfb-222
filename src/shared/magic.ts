// 常用魔数与工具函数

export const MAGICS = {
  uImage: Buffer.from([0x27, 0x05, 0x19, 0x56]),
  trx: Buffer.from([0x48, 0x44, 0x52, 0x30]), // HDR0
  squashfs: Buffer.from([0x68, 0x73, 0x71, 0x73]), // hsqs (小端)
  squashfsBe: Buffer.from([0x73, 0x71, 0x73, 0x68]), // shsq (大端)
  cramfs: Buffer.from([0x45, 0x3d, 0xcd, 0x28]),
  gzip: Buffer.from([0x1f, 0x8b]),
  xz: Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]),
  lzmaAlone: Buffer.from([0x5d, 0x00, 0x00]), // 常见 LZMA alone 属性头
  lzmaAloneAlt: Buffer.from([0x5d, 0x00, 0x80]),
  elf: Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
  pem: '-----BEGIN',
} as const;

/** 在 buf 中查找全部 magic 出现位置(4 字节对齐扫描,步长 1 保证不遗漏) */
export function findMagic(buf: Buffer, magic: Buffer, maxHits = 64): number[] {
  const hits: number[] = [];
  if (magic.length === 0) return hits;
  const limit = buf.length - magic.length;
  for (let i = 0; i <= limit; i++) {
    if (buf[i] === magic[0] && buf.subarray(i, i + magic.length).equals(magic)) {
      hits.push(i);
      if (hits.length >= maxHits) break;
    }
  }
  return hits;
}

/** 按大端 u32 魔数扫描(CRAMFS magic 0x28CD3D45 以整数形式存储) */
export function findBeU32(buf: Buffer, magic: number, maxHits = 64): number[] {
  const hits: number[] = [];
  const limit = buf.length - 4;
  for (let i = 0; i <= limit; i++) {
    if (buf.readUInt32BE(i) === magic) {
      hits.push(i);
      if (hits.length >= maxHits) break;
    }
  }
  return hits;
}

export function hex(n: number, prefix = '0x'): string {
  return `${prefix}${n.toString(16).toUpperCase()}`;
}

export function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : 2)} ${units[i]}`;
}

/** 安全读取:越界返回 null 而不是抛异常 */
export function safeU32(buf: Buffer, offset: number, bigEndian = false): number | null {
  if (offset < 0 || offset + 4 > buf.length) return null;
  return bigEndian ? buf.readUInt32BE(offset) : buf.readUInt32LE(offset);
}

export function safeU16(buf: Buffer, offset: number, bigEndian = false): number | null {
  if (offset < 0 || offset + 2 > buf.length) return null;
  return bigEndian ? buf.readUInt16BE(offset) : buf.readUInt16LE(offset);
}

export function modeToOctal(mode: number): string {
  return (mode & 0o7777).toString(8).padStart(4, '0');
}

/** 从二进制中抽取可打印字符串(长度 >= 4) */
export function extractStrings(buf: Buffer, minLen = 4, maxCount = 4000): string[] {
  const out: string[] = [];
  let cur: number[] = [];
  for (let i = 0; i < buf.length && out.length < maxCount; i++) {
    const b = buf[i];
    if (b >= 0x20 && b < 0x7f) {
      cur.push(b);
    } else {
      if (cur.length >= minLen) out.push(Buffer.from(cur).toString('latin1'));
      cur = [];
    }
  }
  if (cur.length >= minLen) out.push(Buffer.from(cur).toString('latin1'));
  return out;
}
