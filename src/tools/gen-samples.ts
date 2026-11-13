// 测试固件样本生成器:
//  - router-v1.bin / router-v2.bin:uImage 头 + gzip 内核区 + SquashFS 魔数 FBFS 根文件系统
//  - camera-trx.bin:TRX 容器 + 分区(内核 + CRAMFS 魔数 FBFS)
//  - corrupted.bin:魔数正确但内部表损坏
//  - truncated.bin:v1 的前 60% 截断
// 所有样本都埋入已知问题,断言见 src/tools/assert-samples.ts
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { buildFsImage, type FsEntry } from '../server/analysis/packed-fs.js';
import { buildElf, fakePrivateKeyPem, fakeCertPem } from '../server/analysis/synthetic-elf.js';
import { makeShadowHash } from '../server/analysis/hashes.js';
import { lzmaCompress } from '../server/analysis/compression.js';

const OUT_DIR = path.resolve(process.cwd(), 'data', 'samples');

/** 构造 64 字节 uImage 头 */
function uImageHeader(payloadSize: number, comp: number, arch = 5 /*MIPS*/, name = 'Router Linux-2.6.31'): Buffer {
  const h = Buffer.alloc(64);
  h.writeUInt32BE(0x27051956, 0);
  h.writeUInt32BE(0x12345678, 4); // hcrc
  h.writeUInt32BE(0, 8); // time
  h.writeUInt32BE(payloadSize, 12); // data size
  h.writeUInt32BE(0x80000000, 16); // load
  h.writeUInt32BE(0x80002000, 20); // ep
  h.writeUInt32BE(0, 24); // dcrc
  h[28] = 0; // os linux
  h[29] = arch;
  h[30] = comp; // 1=gzip 3=lzma
  h[31] = 2; // kernel
  h.write(name, 32, 'latin1');
  return h;
}

/** TRX 头(28 字节),分区偏移 0x10/0x14/0x18 */
function trxHeader(totalLen: number, offs: number[]): Buffer {
  const h = Buffer.alloc(28);
  h.write('HDR0', 0, 'latin1');
  h.writeUInt32BE(totalLen, 4);
  h.writeUInt32BE(0, 8); // crc
  h.writeUInt16BE(0, 12); // flags
  h.writeUInt16BE(1, 14); // version
  h.writeUInt32BE(offs[0] ?? 0, 16);
  h.writeUInt32BE(offs[1] ?? 0, 20);
  h.writeUInt32BE(offs[2] ?? 0, 24);
  return h;
}

const shadowV1 = [
  `root:${makeShadowHash('sha512crypt', 'admin')}:19000:0:99999:7:::`,
  `admin:${makeShadowHash('md5crypt', '123456')}:19000:0:99999:7:::`,
  `support:${makeShadowHash('sha256crypt', 'password123')}:19000:0:99999:7:::`,
  `guest:${makeShadowHash('sha512crypt', 'a-very-strong-passphrase-9f3k')}:19000:0:99999:7:::`,
  'bin:*:19000:0:99999:7:::',
].join('\n');

const shadowV2 = [
  `root:${makeShadowHash('sha512crypt', 'a-very-strong-passphrase-9f3k')}:19000:0:99999:7:::`,
  `admin:${makeShadowHash('sha512crypt', 'rotated-strong-pw-77q')}:19000:0:99999:7:::`,
  `support:${makeShadowHash('sha512crypt', 'support-strong-2026')}:19000:0:99999:7:::`,
  'guest:*:19000:0:99999:7:::',
  'bin:*:19000:0:99999:7:::',
].join('\n');

function busyboxElf(version: string): Buffer {
  return buildElf({
    machine: 8, // MIPS
    bigEndian: true,
    imports: ['system', 'popen', 'fork', 'execve', 'socket', 'strcpy', 'printf', 'getenv'],
    banner: `BusyBox v${version} (2024-01-05) multi-call binary.\nUsage: busybox`,
  });
}

function dropbearElf(version: string): Buffer {
  return buildElf({
    machine: 8,
    bigEndian: true,
    imports: ['socket', 'bind', 'listen', 'accept', 'crypt', 'setuid'],
    banner: `Dropbear SSH v${version}`,
  });
}

function opensslElf(version: string): Buffer {
  return buildElf({
    machine: 8,
    bigEndian: true,
    imports: ['SSL_new', 'SSL_connect', 'EVP_DigestInit_ex', 'BIO_new'],
    banner: `OpenSSL ${version} 11 Sep 2013`,
  });
}

const rcSV1 = `#!/bin/sh
# 启动脚本 v1(故意包含风险配置)
mount -t proc proc /proc
mkdir -p /var/log
telnetd -l /bin/sh &
dropbear -p 22 &
httpd -p 80 -h /www &
upnpd -f /etc/upnp.conf &
snmpd -c public &
iptables -F
chmod -R 777 /tmp
wget http://192.168.1.2/bootstrap.sh | sh &
`;

const rcSV2 = `#!/bin/sh
# 启动脚本 v2(修复部分问题)
mount -t proc proc /proc
mkdir -p /var/log
dropbear -p 22 &
httpd -p 443 -S -h /www &
snmpd -c internal-ro-community &
`;

const httpdConfV1 = `# Web 管理配置
listen 0.0.0.0:80
admin_user=root
admin_password=admin
auth_key=AKIA-FIRMWARE-FACTORY-KEY
debug=1
`;

const httpdConfV2 = `# Web 管理配置
listen 127.0.0.1:8443
admin_user=root
# 口令已迁移到首次启动强制设置
debug=0
`;

function entriesV1(): FsEntry[] {
  return [
    { path: '/etc', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/etc/init.d', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/etc/init.d/rcS', type: 'file', mode: 0o755, uid: 0, gid: 0, data: Buffer.from(rcSV1) },
    { path: '/etc/shadow', type: 'file', mode: 0o640, uid: 0, gid: 42, data: Buffer.from(shadowV1) },
    { path: '/etc/passwd', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\n') },
    { path: '/etc/httpd.conf', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from(httpdConfV1) },
    { path: '/etc/snmpd.conf', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('rocommunity public\nrwcommunity private\n') },
    { path: '/etc/dropbear', type: 'dir', mode: 0o700, uid: 0, gid: 0 },
    { path: '/etc/dropbear/id_rsa', type: 'file', mode: 0o600, uid: 0, gid: 0, data: Buffer.from(fakePrivateKeyPem()) },
    { path: '/etc/certs', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/etc/certs/server.pem', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from(fakeCertPem()) },
    { path: '/bin', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/bin/busybox', type: 'file', mode: 0o755, uid: 0, gid: 0, data: busyboxElf('1.27.2') },
    { path: '/usr', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/usr/sbin', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/usr/sbin/dropbear', type: 'file', mode: 0o755, uid: 0, gid: 0, data: dropbearElf('2014.65') },
    { path: '/usr/lib', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/usr/lib/libssl.so', type: 'file', mode: 0o755, uid: 0, gid: 0, data: opensslElf('1.0.1f') },
    { path: '/www', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/www/index.html', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('<html><body>Router Admin v1</body></html>') },
    { path: '/www/backdoor_accounts.txt', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('root:admin\nadmin:admin123\nsupport:password123\n') },
    { path: '/tmp/log', type: 'symlink', mode: 0o777, uid: 0, gid: 0, linkTarget: '/var/log' },
  ];
}

function entriesV2(): FsEntry[] {
  const list = entriesV1().filter(
    (e) => e.path !== '/www/backdoor_accounts.txt' && e.path !== '/etc/dropbear/id_rsa'
  );
  const replace = new Map<string, FsEntry>([
    ['/etc/init.d/rcS', { path: '/etc/init.d/rcS', type: 'file', mode: 0o755, uid: 0, gid: 0, data: Buffer.from(rcSV2) }],
    ['/etc/shadow', { path: '/etc/shadow', type: 'file', mode: 0o640, uid: 0, gid: 42, data: Buffer.from(shadowV2) }],
    ['/etc/httpd.conf', { path: '/etc/httpd.conf', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from(httpdConfV2) }],
    ['/etc/snmpd.conf', { path: '/etc/snmpd.conf', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('rocommunity internal-ro-community\n') }],
    ['/bin/busybox', { path: '/bin/busybox', type: 'file', mode: 0o755, uid: 0, gid: 0, data: busyboxElf('1.36.1') }],
    ['/usr/sbin/dropbear', { path: '/usr/sbin/dropbear', type: 'file', mode: 0o755, uid: 0, gid: 0, data: dropbearElf('2022.83') }],
    ['/usr/lib/libssl.so', { path: '/usr/lib/libssl.so', type: 'file', mode: 0o755, uid: 0, gid: 0, data: opensslElf('3.0.12') }],
    ['/www/index.html', { path: '/www/index.html', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('<html><body>Router Admin v2</body></html>') }],
  ]);
  const merged = list.map((e) => replace.get(e.path) ?? e);
  merged.push({ path: '/etc/security', type: 'dir', mode: 0o755, uid: 0, gid: 0 });
  merged.push({ path: '/etc/security/policy.conf', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('min_password_len=12\nlockout_threshold=5\n') });
  return merged;
}

function padTo(b: Buffer, align: number, fill = 0xff): Buffer {
  const rem = b.length % align;
  if (rem === 0) return b;
  return Buffer.concat([b, Buffer.alloc(align - rem, fill)]);
}

async function buildRouter(entries: FsEntry[], tag: string): Promise<Buffer> {
  const fsImg = buildFsImage(entries, 'squashfs-le');
  // 内核:gzip 压缩的伪内核(携带版本字符串)
  const kernelRaw = Buffer.concat([
    Buffer.from(`Linux version 2.6.31 (build@${tag}) #1 MIPS\n`, 'latin1'),
    Buffer.alloc(512, 0x41),
  ]);
  const kernelGz = zlib.gzipSync(kernelRaw);
  const header = uImageHeader(kernelGz.length, 1 /*gzip*/);
  const kernelPart = Buffer.concat([header, kernelGz]);
  const aligned = padTo(kernelPart, 0x100, 0x00);
  return Buffer.concat([aligned, fsImg, Buffer.alloc(64, 0xff)]);
}

async function buildCameraTrx(): Promise<Buffer> {
  // 摄像头:TRX 容器,LZMA 内核 + CRAMFS 魔数 FS,内含 ARM 架构 ELF
  const entries: FsEntry[] = [
    { path: '/etc', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/etc/init.d', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    {
      path: '/etc/init.d/rcS', type: 'file', mode: 0o755, uid: 0, gid: 0,
      data: Buffer.from('#!/bin/sh\ntelnetd &\nhttpd -p 80 &\n'),
    },
    {
      path: '/etc/shadow', type: 'file', mode: 0o640, uid: 0, gid: 42,
      data: Buffer.from(`root:${makeShadowHash('sha512crypt', 'camera')}:19000:0:99999:7:::\n`),
    },
    { path: '/bin', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    {
      path: '/bin/busybox', type: 'file', mode: 0o755, uid: 0, gid: 0,
      data: buildElf({ machine: 40 /*ARM*/, imports: ['system', 'socket', 'printf'], banner: 'BusyBox v1.20.2' }),
    },
  ];
  const fsImg = buildFsImage(entries, 'cramfs');
  const kernelLzma = await lzmaCompress(Buffer.from('ARM camera kernel 3.4.0\n' + 'K'.repeat(4096), 'latin1'));
  const part1Off = 28; // 紧跟 TRX 头
  const part1 = padTo(kernelLzma, 4, 0x00);
  const part2Off = part1Off + part1.length;
  const total = part2Off + fsImg.length;
  const header = trxHeader(total, [part1Off, part2Off, 0]);
  return Buffer.concat([header, part1, fsImg]);
}

function buildCorrupted(): Buffer {
  // 魔数正确、超级块尺寸巨大、TOC 计数被改成 99999(解析应截断保护)
  const good = buildFsImage(
    [{ path: '/etc', type: 'dir', mode: 0o755, uid: 0, gid: 0 }],
    'squashfs-le'
  );
  const bad = Buffer.from(good);
  bad.writeUInt32LE(0xffffffff, 0x28); // bytes_used 越界
  const tocOff = bad.indexOf('FBFS1');
  if (tocOff >= 5) bad.writeUInt32LE(99999, tocOff + 5);
  return bad;
}

export async function main(): Promise<void> {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const v1 = await buildRouter(entriesV1(), 'v1');
  const v2 = await buildRouter(entriesV2(), 'v2');
  const trx = await buildCameraTrx();
  const corrupted = buildCorrupted();
  const truncated = v1.subarray(0, Math.floor(v1.length * 0.6));

  const files: Array<[string, Buffer]> = [
    ['router-v1.bin', v1],
    ['router-v2.bin', v2],
    ['camera-trx.bin', trx],
    ['corrupted.bin', corrupted],
    ['truncated.bin', truncated],
  ];
  for (const [name, buf] of files) {
    fs.writeFileSync(path.join(OUT_DIR, name), buf);
    console.log(`生成 ${name}: ${buf.length} 字节`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
