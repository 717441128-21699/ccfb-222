// 合成最小 ELF:合法 ELF 头 + 程序头 + 节表(.dynsym/.dynstr/.shstrtab),
// 可被本工具 parseElf 解析出架构与导入函数,字符串中携带组件版本。
import crypto from 'node:crypto';

export interface ElfOptions {
  machine: number; // EM_*
  bigEndian?: boolean;
  is64?: boolean;
  imports: string[];
  /** 附加字符串(组件版本 banner 等) */
  banner?: string;
}

export function buildElf(opts: ElfOptions): Buffer {
  const be = opts.bigEndian ?? false;
  const is64 = opts.is64 ?? false;
  const ehSize = is64 ? 64 : 52;
  const phentSize = is64 ? 56 : 32;
  const shentSize = is64 ? 64 : 40;

  // 字符串表内容
  const shstr = ['\x00', '.shstrtab\x00', '.dynsym\x00', '.dynstr\x00', '.banner\x00'];
  const shstrBuf = Buffer.concat(shstr.map((s) => Buffer.from(s, 'latin1')));
  const nameOff: Record<string, number> = {};
  let acc = 0;
  for (const s of shstr) {
    nameOff[s.replace(/\x00/g, '')] = acc;
    acc += s.length;
  }

  const dynstrParts = ['\x00', ...opts.imports.map((s) => s + '\x00')];
  const dynstrBuf = Buffer.concat(dynstrParts.map((s) => Buffer.from(s, 'latin1')));
  const dynNames: Array<{ name: string; off: number }> = [];
  acc = 0;
  for (const s of dynstrParts) {
    dynNames.push({ name: s.replace('\x00', ''), off: acc });
    acc += s.length;
  }
  const bannerBuf = Buffer.from(opts.banner ? opts.banner + '\x00' : '\x00', 'latin1');

  // .dynsym:每个符号 16(32)/24(64) 字节,st_shndx=0 (SHN_UNDEF => 导入)
  const symSize = is64 ? 24 : 16;
  const dynsymBuf = Buffer.alloc(symSize * Math.max(1, opts.imports.length + 1));
  opts.imports.forEach((imp, i) => {
    const base = (i + 1) * symSize;
    const w32 = (o: number, v: number) => (be ? dynsymBuf.writeUInt32BE(v, base + o) : dynsymBuf.writeUInt32LE(v, base + o));
    w32(0, dynNames.find((d) => d.name === imp)?.off ?? 0); // st_name
    dynsymBuf[base + (is64 ? 4 : 12)] = 0x12; // st_info GLOBAL FUNC
    dynsymBuf.writeUInt16LE(0, base + (is64 ? 6 : 6)); // st_shndx = UND
  });

  // 布局
  const phnum = 1;
  const shnum = 5; // NULL + .dynsym + .dynstr + .shstrtab + .banner
  let cursor = ehSize + phentSize * phnum;
  const layout = [
    { name: '.dynsym', buf: dynsymBuf, type: 11 /*DYNSYM*/, link: 2, entsize: symSize },
    { name: '.dynstr', buf: dynstrBuf, type: 3 /*STRTAB*/, link: 0, entsize: 0 },
    { name: '.shstrtab', buf: shstrBuf, type: 3, link: 0, entsize: 0 },
    { name: '.banner', buf: bannerBuf, type: 1 /*PROGBITS*/, link: 0, entsize: 0 },
  ];
  const placed = layout.map((l) => {
    const off = cursor;
    cursor += l.buf.length;
    return { ...l, offset: off };
  });
  const shoff = cursor;
  const total = shoff + shentSize * shnum;
  const elf = Buffer.alloc(total);

  // ELF 头
  elf[0] = 0x7f; elf[1] = 0x45; elf[2] = 0x4c; elf[3] = 0x46;
  elf[4] = is64 ? 2 : 1;
  elf[5] = be ? 2 : 1;
  elf[6] = 1; // EI_VERSION
  const w16 = (o: number, v: number) => (be ? elf.writeUInt16BE(v, o) : elf.writeUInt16LE(v, o));
  const w32h = (o: number, v: number) => (be ? elf.writeUInt32BE(v, o) : elf.writeUInt32LE(v, o));
  const w64h = (o: number, v: bigint) => (be ? elf.writeBigUInt64BE(v, o) : elf.writeBigUInt64LE(v, o));
  w16(16, 2); // ET_EXEC
  w16(18, opts.machine);
  w32h(20, 1); // version
  if (is64) {
    w64h(24, 0x400000n);
    w64h(32, BigInt(ehSize)); // phoff
    w64h(40, BigInt(shoff));
    w16(52, 64); w16(54, phentSize); w16(56, phnum);
    w16(58, shentSize); w16(60, shnum); w16(62, 3); // shstrndx=3
  } else {
    w32h(24, 0x400000);
    w32h(28, ehSize);
    w32h(32, shoff);
    w16(40, 52); w16(42, phentSize); w16(44, phnum);
    w16(46, shentSize); w16(48, shnum); w16(50, 3);
  }
  // 程序头(PT_LOAD)
  const ph = ehSize;
  w32h(ph, 1); // PT_LOAD
  if (is64) {
    w32h(ph + 4, 5); // flags R+X
    w64h(ph + 8, 0n); w64h(ph + 16, 0x400000n); w64h(ph + 24, 0x400000n);
    w64h(ph + 32, BigInt(total)); w64h(ph + 40, BigInt(total)); w64h(ph + 48, 0x1000n);
  } else {
    w32h(ph + 4, 0); w32h(ph + 8, 0x400000); w32h(ph + 12, 0x400000);
    w32h(ph + 16, total); w32h(ph + 20, total); w32h(ph + 24, 5); w32h(ph + 28, 0x1000);
  }
  // 数据
  for (const p of placed) p.buf.copy(elf, p.offset);
  // 节表:0 = NULL
  const secByName = new Map(placed.map((p) => [p.name, p]));
  const secOrder = [null, '.dynsym', '.dynstr', '.shstrtab', '.banner'];
  secOrder.forEach((name, idx) => {
    const base = shoff + idx * shentSize;
    if (!name) return;
    const p = secByName.get(name)!;
    w32h(base, nameOff[name] ?? 0);
    w32h(base + 4, p.type);
    w64Or32(elf, base + (is64 ? 8 : 8), 5, is64, be); // flags
    const offField = base + (is64 ? 24 : 16);
    const sizeField = base + (is64 ? 32 : 20);
    const linkField = base + (is64 ? 40 : 24);
    const entField = base + (is64 ? 56 : 36);
    if (is64) {
      (be ? elf.writeBigUInt64BE(BigInt(p.offset), offField) : elf.writeBigUInt64LE(BigInt(p.offset), offField));
      (be ? elf.writeBigUInt64BE(BigInt(p.buf.length), sizeField) : elf.writeBigUInt64LE(BigInt(p.buf.length), sizeField));
      w32h(linkField, p.link);
      (be ? elf.writeBigUInt64BE(BigInt(p.entsize), entField) : elf.writeBigUInt64LE(BigInt(p.entsize), entField));
    } else {
      w32h(offField, p.offset);
      w32h(sizeField, p.buf.length);
      w32h(linkField, p.link);
      w32h(entField, p.entsize);
    }
  });
  return elf;
}

function w64Or32(_buf: Buffer, _off: number, _v: number, _is64: boolean, _be: boolean): void {
  // flags 字段简化:保持 0 即可,解析器不依赖
}

/** 生成自签名风格的 PEM 占位内容(样本用,非真实密钥材料) */
export function fakePrivateKeyPem(): string {
  const b64 = crypto.randomBytes(220).toString('base64').match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN RSA PRIVATE KEY-----\n${b64}\n-----END RSA PRIVATE KEY-----\n`;
}

export function fakeCertPem(cn = 'Router-Factory-Default'): string {
  const b64 = crypto.randomBytes(300).toString('base64').match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN CERTIFICATE-----\nSubject: CN=${cn}\n${b64}\n-----END CERTIFICATE-----\n`;
}
