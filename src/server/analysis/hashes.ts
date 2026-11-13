// 口令哈希识别与字典破解
// 支持:$1$ (MD5-crypt)、$5$ (SHA256-crypt)、$6$ (SHA512-crypt),
// 以及裸 MD5/SHA1/SHA256 十六进制哈希。传统 DES crypt 仅识别标记(弱/遗留)。
import crypto from 'node:crypto';

const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function b64From24bit(a: number, b: number, c: number, n: number): string {
  let v = (a << 16) | (b << 8) | c;
  let out = '';
  for (let i = 0; i < n; i++) {
    out += ITOA64[v & 0x3f];
    v >>= 6;
  }
  return out;
}

function md5(buf: Buffer): Buffer {
  return crypto.createHash('md5').update(buf).digest();
}

/** $1$ MD5-crypt(返回不含盐前缀的 22 位编码) */
export function md5Crypt(password: string, salt: string): string {
  const pw = Buffer.from(password, 'utf8');
  const s = Buffer.from(salt, 'utf8');
  const ctx1 = Buffer.concat([pw, Buffer.from('$1$'), s]);
  const alt = md5(Buffer.concat([pw, s, pw]));
  const ctx1Parts: Buffer[] = [ctx1];
  for (let i = pw.length; i > 0; i -= 16) {
    ctx1Parts.push(alt.subarray(0, Math.min(16, i)));
  }
  let bits = pw.length;
  const zeroOne: number[] = [];
  while (bits) {
    zeroOne.push(bits & 1 ? 0 : pw[0]);
    bits >>= 1;
  }
  ctx1Parts.push(Buffer.from(zeroOne));
  let final = md5(Buffer.concat(ctx1Parts));
  for (let i = 0; i < 1000; i++) {
    const parts: Buffer[] = [];
    parts.push(i & 1 ? pw : final);
    if (i % 3) parts.push(s);
    if (i % 7) parts.push(pw);
    parts.push(i & 1 ? final : pw);
    final = md5(Buffer.concat(parts));
  }
  const b = final;
  return (
    b64From24bit(b[0], b[6], b[12], 4) +
    b64From24bit(b[1], b[7], b[13], 4) +
    b64From24bit(b[2], b[8], b[14], 4) +
    b64From24bit(b[3], b[9], b[15], 4) +
    b64From24bit(b[4], b[10], b[5], 4) +
    b64From24bit(0, 0, b[11], 2)
  );
}

type ShaAlgo = 'sha256' | 'sha512';

function shaHash(algo: ShaAlgo, buf: Buffer): Buffer {
  return crypto.createHash(algo).update(buf).digest();
}

/** $5$ / $6$ SHA-crypt */
export function shaCrypt(password: string, salt: string, algo: ShaAlgo, rounds = 5000): string {
  const pw = Buffer.from(password, 'utf8');
  const s = Buffer.from(salt, 'utf8');
  const blockSize = algo === 'sha512' ? 64 : 32;
  const digestSize = algo === 'sha512' ? 64 : 32;

  const aCtx = crypto.createHash(algo);
  aCtx.update(pw).update(s);
  const altCtx = crypto.createHash(algo);
  altCtx.update(pw).update(s).update(pw);
  let alt = altCtx.digest();

  // A 中按密码长度追加 alt
  for (let i = pw.length; i > 0; i -= digestSize) {
    aCtx.update(alt.subarray(0, Math.min(digestSize, i)));
  }
  for (let bits = pw.length; bits; bits >>= 1) {
    if (bits & 1) aCtx.update(Buffer.alloc(1));
    else aCtx.update(pw.subarray(0, 1));
  }
  let final = aCtx.digest();

  // P 缓冲区
  const pCtx = crypto.createHash(algo);
  for (let i = 0; i < pw.length; i++) pCtx.update(pw);
  const pBuf = repeatTo(pCtx.digest(), pw.length);
  // S 缓冲区
  const sCtx = crypto.createHash(algo);
  for (let i = 0; i < 16 + final[0]; i++) sCtx.update(s);
  const sBuf = repeatTo(sCtx.digest(), s.length);

  for (let i = 0; i < rounds; i++) {
    const ctx = crypto.createHash(algo);
    ctx.update(i & 1 ? pBuf : final);
    if (i % 3) ctx.update(sBuf);
    if (i % 7) ctx.update(pBuf);
    ctx.update(i & 1 ? final : pBuf);
    final = ctx.digest();
  }

  return algo === 'sha512' ? encodeSha512(final) : encodeSha256(final);
}

function repeatTo(buf: Buffer, len: number): Buffer {
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i += buf.length) buf.copy(out, i, 0, Math.min(buf.length, len - i));
  return out;
}

function encodeSha512(b: Buffer): string {
  const groups: Array<[number, number, number, number]> = [
    [0, 21, 42, 4],
    [22, 43, 1, 4],
    [44, 2, 23, 4],
    [3, 24, 45, 4],
    [25, 46, 4, 4],
    [47, 5, 26, 4],
    [6, 27, 48, 4],
    [28, 49, 7, 4],
    [50, 8, 29, 4],
    [9, 30, 51, 4],
    [31, 52, 10, 4],
    [53, 11, 32, 4],
    [12, 33, 54, 4],
    [34, 55, 13, 4],
    [56, 14, 35, 4],
    [15, 36, 57, 4],
    [37, 58, 16, 4],
    [59, 17, 38, 4],
    [18, 39, 60, 4],
    [40, 61, 19, 4],
    [62, 20, 41, 4],
  ];
  let out = groups.map(([x, y, z, n]) => b64From24bit(b[x], b[y], b[z], n)).join('');
  out += b64From24bit(0, 0, b[63], 2);
  return out;
}

function encodeSha256(b: Buffer): string {
  const groups: Array<[number, number, number, number]> = [
    [0, 10, 20, 4],
    [21, 1, 11, 4],
    [12, 22, 2, 4],
    [3, 13, 23, 4],
    [24, 4, 14, 4],
    [15, 25, 5, 4],
    [6, 16, 26, 4],
    [27, 7, 17, 4],
    [18, 28, 8, 4],
    [9, 19, 29, 4],
  ];
  let out = groups.map(([x, y, z, n]) => b64From24bit(b[x], b[y], b[z], n)).join('');
  out += b64From24bit(0, b[31], b[30], 3);
  return out;
}

export type HashKind = 'md5crypt' | 'sha256crypt' | 'sha512crypt' | 'des' | 'raw-md5' | 'raw-sha1' | 'raw-sha256' | 'unknown';

export function identifyHash(hash: string): HashKind {
  if (hash.startsWith('$1$')) return 'md5crypt';
  if (hash.startsWith('$5$')) return 'sha256crypt';
  if (hash.startsWith('$6$')) return 'sha512crypt';
  if (/^[A-Za-z0-9./]{13}$/.test(hash)) return 'des';
  if (/^[a-f0-9]{32}$/i.test(hash)) return 'raw-md5';
  if (/^[a-f0-9]{40}$/i.test(hash)) return 'raw-sha1';
  if (/^[a-f0-9]{64}$/i.test(hash)) return 'raw-sha256';
  return 'unknown';
}

/** 校验密码是否匹配哈希 */
export function verifyHash(hash: string, password: string): boolean {
  const kind = identifyHash(hash);
  try {
    if (kind === 'md5crypt') {
      const salt = hash.split('$')[2] ?? '';
      return md5Crypt(password, salt) === hash.split('$')[3];
    }
    if (kind === 'sha256crypt' || kind === 'sha512crypt') {
      const parts = hash.split('$');
      const salt = parts[2]?.split('=')[1] ?? parts[2] ?? '';
      const algo: ShaAlgo = kind === 'sha256crypt' ? 'sha256' : 'sha512';
      const roundsMatch = hash.match(/rounds=(\d+)/);
      const encoded = shaCrypt(password, salt, algo, roundsMatch ? parseInt(roundsMatch[1], 10) : 5000);
      return encoded === parts[parts.length - 1];
    }
    if (kind === 'raw-md5') return digestHex('md5', password) === hash.toLowerCase();
    if (kind === 'raw-sha1') return digestHex('sha1', password) === hash.toLowerCase();
    if (kind === 'raw-sha256') return digestHex('sha256', password) === hash.toLowerCase();
  } catch {
    return false;
  }
  return false;
}

function digestHex(algo: string, s: string): string {
  return crypto.createHash(algo).update(s, 'utf8').digest('hex');
}

/** 用字典破解单个哈希,返回命中的明文或 null */
export function crackHash(hash: string, wordlist: string[]): string | null {
  const kind = identifyHash(hash);
  if (kind === 'des' || kind === 'unknown') return null;
  for (const w of wordlist) {
    if (verifyHash(hash, w)) return w;
  }
  return null;
}

/** 生成 shadow 行使用的标准格式哈希(样本生成器复用,保证可被破解) */
export function makeShadowHash(kind: Exclude<HashKind, 'des' | 'unknown' | `raw-${string}`>, password: string, salt = 'aB3xK9qZ'): string {
  if (kind === 'md5crypt') return `$1$${salt}$${md5Crypt(password, salt)}`;
  if (kind === 'sha256crypt') return `$5$${salt}$${shaCrypt(password, salt, 'sha256')}`;
  return `$6$${salt}$${shaCrypt(password, salt, 'sha512')}`;
}
