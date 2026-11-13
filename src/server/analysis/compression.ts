// 压缩段处理:gzip / xz 用成熟库,LZMA 用 lzma 包 + 自写 raw 头适配
import zlib from 'node:zlib';
import LZMA from 'lzma';
import xzMod from 'xz-decompress';

const { XzReadableStream } = xzMod;

export class DecompressError extends Error {
  constructor(
    message: string,
    readonly kind: 'gzip' | 'xz' | 'lzma'
  ) {
    super(message);
    this.name = 'DecompressError';
  }
}

/** gzip 解压,容忍尾部多余字节(固件里 gzip 段后常有 padding) */
export function gunzip(input: Buffer): Buffer {
  try {
    return zlib.gunzipSync(input, { finishFlush: zlib.constants.Z_SYNC_FLUSH });
  } catch (e) {
    // 截断的镜像:尝试解出已能解的部分
    try {
      const out = zlib.inflateRawSync(stripGzipWrapper(input), {
        finishFlush: zlib.constants.Z_SYNC_FLUSH,
      });
      if (out.length > 0) return out;
    } catch {
      /* fall through */
    }
    throw new DecompressError((e as Error).message, 'gzip');
  }
}

/** 去掉 gzip 封装头,取 raw deflate 流 */
function stripGzipWrapper(input: Buffer): Buffer {
  let off = 10;
  const flg = input[3] ?? 0;
  if (flg & 0x04) {
    const xlen = input.readUInt16LE(off);
    off += 2 + xlen;
  }
  if (flg & 0x08) {
    while (off < input.length && input[off] !== 0) off++;
    off++;
  }
  if (flg & 0x10) {
    while (off < input.length && input[off] !== 0) off++;
    off++;
  }
  if (flg & 0x02) off += 2;
  return input.subarray(off);
}

export async function xzDecompress(input: Buffer): Promise<Buffer> {
  try {
    const stream = new XzReadableStream(
      new Blob([new Uint8Array(input)]).stream()
    );
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) chunks.push(value);
    }
    return Buffer.concat(chunks.map((c) => Buffer.from(c)));
  } catch (e) {
    throw new DecompressError((e as Error).message, 'xz');
  }
}

function lzmaDecompressAsync(input: Uint8Array): Promise<Buffer | null> {
  return new Promise((resolve, reject) => {
    try {
      LZMA.decompress(input, (result, err) => {
        if (err) reject(err);
        else if (result == null) resolve(null);
        else if (typeof result === 'string') resolve(Buffer.from(result, 'latin1'));
        else resolve(Buffer.from(result));
      });
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * LZMA 解压。固件中常见两种:
 *  1. .lzma alone 流(13 字节 props/dict/size 头 + 压缩数据)
 *  2. raw LZMA(无 13 字节头,uImage 内核常见)——尝试合成头
 */
export async function lzmaDecompress(input: Buffer): Promise<Buffer> {
  // 先按标准 alone 流解
  try {
    const out = await lzmaDecompressAsync(new Uint8Array(input));
    if (out && out.length > 0) return out;
  } catch {
    /* 尝试 raw 适配 */
  }
  // raw LZMA:用首字节 props 合成 alone 头,uncompressed size 置 0xFFFF...(未知)
  if (input.length >= 1) {
    const header = Buffer.alloc(13);
    header[0] = input[0];
    header.writeUInt32LE(0x00800000, 1); // 8 MiB 字典
    header.writeUInt32LE(0xffffffff, 5);
    header.writeUInt32LE(0xffffffff, 9);
    try {
      const out = await lzmaDecompressAsync(
        new Uint8Array(Buffer.concat([header, input]))
      );
      if (out && out.length > 0) return out;
    } catch {
      /* fall through */
    }
  }
  throw new DecompressError('LZMA 流无法识别或数据已截断', 'lzma');
}

/** LZMA alone 压缩(样本生成用,保证能被自己的解压路径读回) */
export function lzmaCompress(input: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    LZMA.compress(new Uint8Array(input), 7, (result, err) => {
      if (err) reject(err);
      else resolve(Buffer.from(result));
    });
  });
}

/** 自动按魔数选择解压方式,返回解压结果与算法名 */
export async function decompressByMagic(
  input: Buffer
): Promise<{ data: Buffer; algo: 'gzip' | 'xz' | 'lzma' }> {
  if (input.length >= 2 && input[0] === 0x1f && input[1] === 0x8b) {
    return { data: gunzip(input), algo: 'gzip' };
  }
  if (
    input.length >= 6 &&
    input[0] === 0xfd &&
    input[1] === 0x37 &&
    input[2] === 0x7a &&
    input[3] === 0x58 &&
    input[4] === 0x5a &&
    input[5] === 0x00
  ) {
    return { data: await xzDecompress(input), algo: 'xz' };
  }
  if (input.length >= 3 && input[0] === 0x5d && (input[1] === 0x00)) {
    return { data: await lzmaDecompress(input), algo: 'lzma' };
  }
  // 无明显魔数时按 LZMA 尝试(uImage 常见 raw 流)
  return { data: await lzmaDecompress(input), algo: 'lzma' };
}
