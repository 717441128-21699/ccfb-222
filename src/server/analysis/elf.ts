// 最小 ELF 解析:架构/字节序/入口/类型,以及动态符号表中的导入函数
import type { ElfInfo } from '../../shared/types.js';
import { extractStrings, hex } from '../../shared/magic.js';

const MACHINES: Record<number, string> = {
  0x02: 'SPARC',
  0x03: 'x86 (i386)',
  0x08: 'MIPS',
  0x14: 'PowerPC',
  0x28: 'ARM',
  0x32: 'IA-64',
  0x3e: 'x86-64',
  0xb7: 'AArch64 (ARM64)',
  0xf3: 'RISC-V',
  0x0802: 'MIPS (备用编码)',
};

const ET_TYPES: Record<number, string> = {
  1: '可重定位 (REL)',
  2: '可执行 (EXEC)',
  3: '动态库 (DYN)',
  4: '核心转储 (CORE)',
};

export function parseElf(buf: Buffer): ElfInfo | null {
  if (buf.length < 64 || buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
    return null;
  }
  try {
    const is64 = buf[4] === 2;
    const bigEndian = buf[5] === 2;
    const r16 = (o: number) => (bigEndian ? buf.readUInt16BE(o) : buf.readUInt16LE(o));
    const r32 = (o: number) => (bigEndian ? buf.readUInt32BE(o) : buf.readUInt32LE(o));
    const r64 = (o: number) => {
      const lo = r32(o);
      const hi = r32(o + 4);
      return (BigInt(hi) << 32n) | BigInt(lo >>> 0);
    };

    const eType = r16(16);
    const machine = r16(18);
    const entry = is64 ? r64(24) : BigInt(r32(24));
    const ePhoff = is64 ? Number(r64(32)) : r32(28);
    const eShoff = is64 ? Number(r64(40)) : r32(32);
    const ePhentsize = r16(is64 ? 54 : 42);
    const ePhnum = r16(is64 ? 56 : 44);
    const eShentsize = r16(is64 ? 58 : 46);
    const eShnum = r16(is64 ? 60 : 48);
    const eShstrndx = r16(is64 ? 62 : 50);

    const { imports, staticLinked } = extractDynamicImports(
      buf, is64, bigEndian, eShoff, eShentsize, eShnum, eShstrndx
    );

    return {
      class: is64 ? '64位' : '32位',
      endian: bigEndian ? '大端' : '小端',
      machine: MACHINES[machine] ?? `未知架构 (#${machine})`,
      type: ET_TYPES[eType] ?? `类型 ${eType}`,
      entry: hex(Number(entry & 0xffffffffn)),
      imports,
      staticLinked,
    };
  } catch {
    return {
      class: buf[4] === 2 ? '64位' : '32位',
      endian: buf[5] === 2 ? '大端' : '小端',
      machine: '解析失败(ELF 可能被截断)',
      type: '未知',
      entry: '0x?',
      imports: [],
      staticLinked: true,
    };
  }
}

interface SectionHeader {
  name: string;
  type: number;
  offset: number;
  size: number;
  link: number;
  entsize: number;
}

/** 从节表读取 .dynsym/.dynstr,挑出 UND(导入)符号 */
function extractDynamicImports(
  buf: Buffer,
  is64: boolean,
  bigEndian: boolean,
  shoff: number,
  shentsize: number,
  shnum: number,
  shstrndx: number
): { imports: string[]; staticLinked: boolean } {
  if (shoff === 0 || shnum === 0 || shoff + shentsize * shnum > buf.length) {
    // 无节表(常见于 strip 后的程序):退化到字符串扫描
    return { imports: fallbackStringImports(buf), staticLinked: true };
  }
  const r32 = (o: number) => (bigEndian ? buf.readUInt32BE(o) : buf.readUInt32LE(o));
  const r64 = (o: number) => BigInt(bigEndian ? buf.readBigUInt64BE(o) : buf.readBigUInt64LE(o));

  const sections: SectionHeader[] = [];
  for (let i = 0; i < shnum; i++) {
    const base = shoff + i * shentsize;
    const nameOff = r32(base);
    const type = r32(base + 4);
    const offset = is64 ? Number(r64(base + 24)) : r32(base + 16);
    const size = is64 ? Number(r64(base + 32)) : r32(base + 20);
    const link = r32(base + 24 - (is64 ? 0 : 0)) && r32(base + (is64 ? 40 : 24));
    const entsize = is64 ? Number(r64(base + 56)) : r32(base + 36);
    sections.push({ name: '', type, offset, size, link, entsize });
    void nameOff;
  }
  // 节名字符串表
  const shstr = sections[shstrndx];
  if (shstr) {
    for (let i = 0; i < sections.length; i++) {
      const base = shoff + i * shentsize;
      const nameOff = r32(base);
      sections[i].name = readCString(buf, shstr.offset + nameOff);
    }
  }
  const dynsym = sections.find((s) => s.name === '.dynsym');
  const dynstr = dynsym ? sections[dynsym.link] : undefined;
  if (!dynsym || !dynstr) {
    return { imports: fallbackStringImports(buf), staticLinked: sections.every((s) => s.name !== '.dynamic') };
  }
  const symSize = dynsym.entsize || (is64 ? 24 : 16);
  const count = Math.floor(dynsym.size / symSize);
  const imports = new Set<string>();
  for (let i = 0; i < count; i++) {
    const base = dynsym.offset + i * symSize;
    const stName = r32(base);
    // st_info 在 4(32位)/4(64位),st_shndx 在 6(32)/6(64)
    const stShndx = r16At(buf, base + (is64 ? 6 : 6), bigEndian);
    const name = readCString(buf, dynstr.offset + stName);
    if (name && stShndx === 0) imports.add(name); // SHN_UNDEF => 导入
  }
  const list = [...imports].filter(Boolean).sort();
  return { imports: list.slice(0, 500), staticLinked: list.length === 0 };
}

function r16At(buf: Buffer, o: number, be: boolean): number {
  return be ? buf.readUInt16BE(o) : buf.readUInt16LE(o);
}

function readCString(buf: Buffer, off: number): string {
  if (off >= buf.length) return '';
  let end = off;
  while (end < buf.length && buf[end] !== 0) end++;
  return buf.subarray(off, end).toString('utf8');
}

/** 节表缺失时的兜底:从字符串里挑常见 libc 导入 */
const FALLBACK_IMPORTS = new Set([
  'printf', 'sprintf', 'snprintf', 'strcpy', 'strncpy', 'strcat', 'system', 'popen',
  'execve', 'fork', 'socket', 'bind', 'listen', 'accept', 'connect', 'recv', 'send',
  'inet_addr', 'inet_ntoa', 'gethostbyname', 'malloc', 'free', 'open', 'read', 'write',
  'close', 'ioctl', 'mmap', 'munmap', 'dlopen', 'dlsym', 'getenv', 'setuid', 'setgid',
  'chmod', 'chown', 'crypt', 'gets', 'fgets', 'memcpy', 'memmove', 'sscanf', 'atoi',
]);

function fallbackStringImports(buf: Buffer): string[] {
  const found = new Set<string>();
  for (const s of extractStrings(buf, 4, 8000)) {
    if (FALLBACK_IMPORTS.has(s)) found.add(s);
  }
  return [...found].sort();
}
