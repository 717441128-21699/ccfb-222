// 离线漏洞库(本地 JSON,不联网)。版本比较为简化语义化比较,
// 覆盖 busybox / openssl / dropbear 三类组件的代表性历史漏洞。
import type { Severity, VulnRecord } from '../../shared/types.js';

interface RawVuln {
  cve: string;
  component: string;
  /** 受影响版本下界(含),省略表示不限 */
  introduced?: string;
  /** 已修复版本(不含),低于此版本受影响 */
  fixedIn: string;
  severity: Severity;
  title: string;
}

const RAW: RawVuln[] = [
  { cve: 'CVE-2022-28391', component: 'busybox', fixedIn: '1.35.0', severity: 'high', title: 'busybox 1.34.x 中 ash/clisp 等 applet 存在网络命名空间逃逸,可绕过防火墙规则' },
  { cve: 'CVE-2021-42378', component: 'busybox', fixedIn: '1.34.0', severity: 'high', title: 'busybox awk applet 堆内存破坏,可导致拒绝服务或代码执行' },
  { cve: 'CVE-2021-42379', component: 'busybox', fixedIn: '1.34.0', severity: 'high', title: 'busybox awk 释放后使用 (UAF)' },
  { cve: 'CVE-2018-1000517', component: 'busybox', fixedIn: '1.29.0', severity: 'critical', title: 'busybox wget 整数下溢导致堆缓冲区溢出,可远程代码执行' },
  { cve: 'CVE-2017-16544', component: 'busybox', fixedIn: '1.27.2', severity: 'medium', title: 'busybox 自动补全 eval 注入,本地提权风险' },
  { cve: 'CVE-2022-30065', component: 'busybox', fixedIn: '1.35.0', severity: 'high', title: 'busybox awk 空指针解引用导致拒绝服务' },
  { cve: 'CVE-2021-42386', component: 'busybox', fixedIn: '1.34.0', severity: 'medium', title: 'busybox awk 释放后使用,可触发崩溃' },
  { cve: 'CVE-2006-6565', component: 'dropbear', fixedIn: '0.49', severity: 'medium', title: 'dropbear 弱随机数导致 SSH 会话密钥可预测' },
  { cve: 'CVE-2012-0920', component: 'dropbear', fixedIn: '2011.54', severity: 'high', title: 'dropbear CRC 校验竞态,远程可造成拒绝服务' },
  { cve: 'CVE-2013-4434', component: 'dropbear', fixedIn: '2013.59', severity: 'medium', title: 'dropbear 退出时清密钥不完整,内存残留敏感信息' },
  { cve: 'CVE-2016-3116', component: 'dropbear', fixedIn: '2015.71', severity: 'high', title: 'dropbear dbclient X11 转发命令注入' },
  { cve: 'CVE-2018-15599', component: 'dropbear', fixedIn: '2018.76', severity: 'medium', title: 'dropbear 本地端口转发访问控制绕过' },
  { cve: 'CVE-2021-36369', component: 'dropbear', fixedIn: '2020.80', severity: 'high', title: 'dropbear 在特定配置下接受已失效的公钥账号' },
  { cve: 'CVE-2014-3566', component: 'openssl', introduced: '1.0.1', fixedIn: '1.0.1j', severity: 'medium', title: 'POODLE: SSLv3 填充降级攻击,可解密流量' },
  { cve: 'CVE-2014-0224', component: 'openssl', introduced: '1.0.1', fixedIn: '1.0.1h', severity: 'critical', title: 'CCS 注入:中间人可协商弱密钥 (ChangeCipherSpec)' },
  // Heartbleed 仅影响 1.0.1 ~ 1.0.1f(1.0.1g 修复),不能只按数字版本比较
  { cve: 'CVE-2014-0160', component: 'openssl', introduced: '1.0.1', fixedIn: '1.0.1g', severity: 'critical', title: 'Heartbleed 心脏出血:越界读取泄露内存中的私钥与口令' },
  { cve: 'CVE-2015-0204', component: 'openssl', introduced: '1.0.1', fixedIn: '1.0.1k', severity: 'high', title: 'FREAK: 允许导出级弱 RSA 密钥协商' },
  { cve: 'CVE-2015-4000', component: 'openssl', fixedIn: '1.0.2', severity: 'high', title: 'Logjam: DHE 导出组降级,可被预计算破解' },
  { cve: 'CVE-2016-2107', component: 'openssl', introduced: '1.0.1', fixedIn: '1.0.1t', severity: 'high', title: 'AES-NI CBC 填充检查缺陷,可解密 TLS 流量' },
  { cve: 'CVE-2016-6304', component: 'openssl', introduced: '1.0.1', fixedIn: '1.0.1u', severity: 'high', title: 'OCSP 状态扩展内存耗尽拒绝服务' },
  { cve: 'CVE-2022-0778', component: 'openssl', fixedIn: '1.1.1n', severity: 'high', title: 'BN_mod_sqrt 无限循环,恶意证书导致拒绝服务' },
  { cve: 'CVE-2021-3711', component: 'openssl', fixedIn: '1.1.1l', severity: 'critical', title: 'SM2 解密缓冲区溢出,可远程代码执行' },
  { cve: 'CVE-2023-0286', component: 'openssl', fixedIn: '1.1.1t', severity: 'high', title: 'X.400 地址类型混淆,可读写任意内存段' },
];

/** 解析版本号为可比较序列:数字段 + 可选字母后缀(OpenSSL 如 1.0.1f → [1,0,1,6]) */
export function parseVersion(v: string): number[] {
  const m = v.toLowerCase().match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[.\-]?([a-z]+)(\d+)?)?/);
  if (!m) return [0];
  const nums = [m[1], m[2] ?? '0', m[3] ?? '0'].map((x) => parseInt(x, 10) || 0);
  // 字母后缀按 a=1、b=2 ... 追加为下一段,保证 1.0.1f < 1.0.1g
  if (m[4] && /^[a-z]$/.test(m[4])) nums.push(m[4].charCodeAt(0) - 96);
  else if (m[4]) nums.push(0);
  if (m[5]) nums.push(parseInt(m[5], 10) || 0);
  return nums;
}

/** a < b 返回 true */
export function versionLt(a: string, b: string): boolean {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y;
  }
  return false;
}

/** 按组件+版本匹配离线漏洞库;introduced 给出受影响下界(同一 minor 分支) */
export function matchVulns(component: string, version: string): VulnRecord[] {
  const comp = component.toLowerCase();
  return RAW.filter((r) => {
    if (r.component !== comp) return false;
    if (!versionLt(version, r.fixedIn)) return false;
    // 有下界时:版本必须 >= introduced(如 Heartbleed 只在 1.0.1 分支)
    if (r.introduced && versionLt(version, r.introduced)) return false;
    return true;
  }).map((r, i) => ({
    id: `${r.cve}-${i}`,
    cve: r.cve,
    component: comp,
    affected: r.introduced ? `${r.introduced} ~ < ${r.fixedIn}` : `< ${r.fixedIn}`,
    severity: r.severity,
    title: r.title,
  }));
}

export function allVulnRecords(): RawVuln[] {
  return RAW;
}
