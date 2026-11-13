// 端到端断言:对生成样本跑完整分析管线,验证已知问题与健壮性
import fs from 'node:fs';
import path from 'node:path';
import { analyze } from '../server/analysis/analyzer.js';
import { diffFirmware } from '../server/analysis/diff.js';
import { buildHtmlReport } from '../server/analysis/report.js';
import { ensureStorage } from '../server/storage.js';
import type { FirmwareMeta, FsNode, Severity } from '../shared/types.js';

ensureStorage();

const SAMPLE_DIR = path.resolve(process.cwd(), 'data', 'samples');
let passed = 0;
let failed = 0;

function check(name: string, cond: boolean, detail = ''): void {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.error(`  ✗ ${name} ${detail}`);
  }
}

function load(name: string): Buffer {
  return fs.readFileSync(path.join(SAMPLE_DIR, name));
}

function fakeMeta(name: string, buf: Buffer, analysis: Awaited<ReturnType<typeof analyze>>): FirmwareMeta {
  return {
    id: name,
    originalName: name,
    size: buf.length,
    sha256: name.repeat(8).slice(0, 64),
    uploadedAt: new Date(0).toISOString(),
    analyzed: true,
    analysis,
  };
}

const sevRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

async function main(): Promise<void> {
  console.log('\n== router-v1.bin(埋点最齐全)==');
  const v1Buf = load('router-v1.bin');
  const v1 = await analyze(v1Buf);
  const segTypes = v1.segments.map((s) => s.type);
  check('识别 uImage 头', segTypes.includes('uImage'));
  check('识别 gzip 压缩段', segTypes.includes('gzip'));
  check('识别 SquashFS 段', segTypes.includes('squashfs'));
  check('文件系统展开成目录树', v1.tree !== null);
  check('树包含 /etc/shadow', JSON.stringify(v1.tree).includes('/etc/shadow'));
  check('树包含 busybox ELF', JSON.stringify(v1.tree).includes('/bin/busybox'));
  check('统计文件数 > 10', v1.stats.fileCount > 10, `实际 ${v1.stats.fileCount}`);

  const titles = v1.findings.map((f) => f.title);
  const allText = JSON.stringify(v1.findings);
  check('发现硬编码口令', titles.some((t) => t.includes('硬编码口令')));
  check('发现私钥', allText.includes('私钥'));
  check('发现证书', allText.includes('X.509 证书'));
  check('shadow 弱口令被字典破解', v1.findings.some((f) => f.cracked && /admin|123456|password123/.test(f.title)),
    v1.findings.filter((f) => f.cracked).map((f) => f.title).join(' | '));
  check('强口令 guest 未被误报破解', !v1.findings.some((f) => f.path === '/etc/shadow' && f.title.includes('guest') && f.cracked));
  check('识别 Telnet 风险服务', v1.services.some((s) => s.name === 'Telnet' && s.risky));
  check('识别 UPnP 服务', v1.services.some((s) => s.name === 'UPnP'));
  check('识别 chmod 777 危险配置', v1.findings.some((f) => f.evidence?.includes('777')));
  check('识别 wget|sh 供应链风险', v1.findings.some((f) => f.evidence?.includes('wget')));
  check('识别 SNMP 默认 community', v1.findings.some((f) => f.title.includes('SNMP')));

  const busybox = v1.components.find((c) => c.name === 'busybox');
  check('识别 busybox 版本 1.27.2', busybox?.version === '1.27.2', busybox?.version);
  check('busybox 命中离线 CVE', (busybox?.vulns.length ?? 0) > 0, String(busybox?.vulns.map((v) => v.cve)));
  const openssl = v1.components.find((c) => c.name === 'openssl');
  check('识别 openssl 1.0.1f 并命中 Heartbleed', Boolean(openssl?.vulns.some((v) => v.cve === 'CVE-2014-0160')));
  const dropbear = v1.components.find((c) => c.name === 'dropbear');
  check('识别 dropbear 版本且命中 CVE', !!dropbear && dropbear.vulns.length > 0, dropbear?.version);

  // ELF 解析
  const busyboxNode = findNode(v1.tree!, '/bin/busybox');
  check('busybox ELF 识别为 MIPS', busyboxNode?.elf?.machine.includes('MIPS') === true, busyboxNode?.elf?.machine);
  check('ELF 显示大端', busyboxNode?.elf?.endian === '大端');
  check('ELF 提取到导入函数', (busyboxNode?.elf?.imports.length ?? 0) >= 4, String(busyboxNode?.elf?.imports));

  console.log('\n== router-v2.bin(补丁版)==');
  const v2 = await analyze(load('router-v2.bin'));
  check('v2 仍正常展开', v2.tree !== null);
  const v2bb = v2.components.find((c) => c.name === 'busybox');
  check('v2 busybox 升级到 1.36.1', v2bb?.version === '1.36.1');
  check('v2 busybox 离线库 0 命中', (v2bb?.vulns.length ?? 0) === 0);
  const v2ssl = v2.components.find((c) => c.name === 'openssl');
  check('v2 openssl 3.0.12 无 Heartbleed', Boolean(v2ssl?.vulns.every((v) => v.cve !== 'CVE-2014-0160')));
  check('v2 删除了后门账号文件', !JSON.stringify(v2.tree).includes('backdoor_accounts'));
  check('v2 移除了私钥文件', !JSON.stringify(v2.tree).includes('id_rsa'));
  check('v2 不再启动 Telnet', !v2.services.some((s) => s.name === 'Telnet'));
  check('v2 风险发现数少于 v1', v2.findings.length < v1.findings.length, `${v2.findings.length} vs ${v1.findings.length}`);

  console.log('\n== camera-trx.bin(TRX + CRAMFS + LZMA + ARM)==');
  const cam = await analyze(load('camera-trx.bin'));
  check('识别 TRX 容器', cam.segments.some((s) => s.type === 'TRX'));
  check('识别 CRAMFS 段', cam.segments.some((s) => s.type === 'cramfs'));
  check('识别 LZMA 压缩段', cam.segments.some((s) => s.type === 'lzma'));
  check('TRX 分区数 >= 2', Number(cam.segments.find((s) => s.type === 'TRX')?.details?.分区数 ?? 0) >= 2);
  const camElf = findNode(cam.tree!, '/bin/busybox');
  check('摄像头 ELF 识别为 ARM', camElf?.elf?.machine.includes('ARM') === true, camElf?.elf?.machine);
  check('摄像头 shadow 弱口令 camera 被破解', cam.findings.some((f) => f.cracked));

  console.log('\n== corrupted.bin(损坏,不得崩溃)==');
  let corruptedOk = true;
  let corrupted;
  try {
    corrupted = await analyze(load('corrupted.bin'));
  } catch (e) {
    corruptedOk = false;
    console.error('    抛出异常:', (e as Error).message);
  }
  check('损坏镜像分析不抛异常', corruptedOk);
  check('损坏镜像产生告警', (corrupted?.warnings.length ?? 0) > 0);
  check('损坏镜像仍返回结构段', (corrupted?.segments.length ?? 0) > 0);

  console.log('\n== truncated.bin(截断,不得崩溃)==');
  let truncatedOk = true;
  let truncated;
  try {
    truncated = await analyze(load('truncated.bin'));
  } catch (e) {
    truncatedOk = false;
    console.error('    抛出异常:', (e as Error).message);
  }
  check('截断镜像分析不抛异常', truncatedOk);
  check('截断镜像有告警或错误提示', (truncated?.warnings.length ?? 0) > 0);
  check('截断镜像仍识别出 uImage', truncated?.segments.some((s) => s.type === 'uImage') === true);

  console.log('\n== 版本差异对比 ==');
  const diff = diffFirmware(fakeMeta('router-v1.bin', v1Buf, v1), fakeMeta('router-v2.bin', load('router-v2.bin'), v2));
  check('对比检测到删除文件(backdoor_accounts)', diff.entries.some((e) => e.change === 'removed' && e.path.includes('backdoor')));
  check('对比检测到修改文件(rcS/shadow)', diff.entries.some((e) => e.change === 'modified' && (e.path.includes('rcS') || e.path.includes('shadow'))));
  check('对比检测到新增文件(policy.conf)', diff.entries.some((e) => e.change === 'added'));
  check('旧版独有风险非空(补丁修复项)', diff.findingsOnlyInA.length > 0);

  console.log('\n== HTML 报告 ==');
  const html = buildHtmlReport(fakeMeta('router-v1.bin', v1Buf, v1));
  check('报告为独立 HTML', html.startsWith('<!doctype html>') && html.includes('</html>'));
  check('报告内联样式无外部资源', !/(src|href)=["']https?:\/\//.test(html));
  check('报告包含风险与 CVE 内容', html.includes('固件安全分析报告') && html.includes('风险发现') && html.includes('Heartbleed'));

  console.log(`\n结果:${passed} 通过,${failed} 失败`);
  if (failed > 0) process.exit(1);
}

function findNode(root: NonNullable<Awaited<ReturnType<typeof analyze>>['tree']>, p: string): FsNode | null {
  let found: FsNode | null = null;
  const walk = (n: NonNullable<typeof root>): void => {
    if (n.path === p) found = n;
    n.children?.forEach(walk);
  };
  walk(root);
  return found;
}

main().catch((e) => {
  console.error('断言脚本异常:', e);
  process.exit(1);
});
