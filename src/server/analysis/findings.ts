// 风险规则引擎:对展开后的文件内容做静态扫描,产出 Finding 列表
import type { Finding, FsNode, ServiceEntry, StartupConfig, Severity } from '../../shared/types.js';
import { identifyHash, crackHash } from './hashes.js';
import { BUILTIN_WORDLIST } from './wordlist.js';

let seq = 0;
const nextId = () => `F${(++seq).toString().padStart(4, '0')}`;

export interface RuleFile {
  path: string;
  content: Buffer;
  node: FsNode;
}

const TEXT_EXT = /\.(conf|cfg|config|ini|sh|rc|txt|xml|json|yaml|yml|env|passwd|shadow|crt|pem|key|pub|html|js|cgi|lua|py|conf\.orig|service|hosts|motd)$/i;
const STARTUP_PATH = /(^|\/)(etc\/(init\.d|rcS\.d|rc[0-6S]\.d)|etc\/(rc\.local|inittab|profile|rcS)|etc\/config\/|usr\/local\/etc\/init\.d)/;
const SENSITIVE_NAME = /(passwd|shadow|httpd|config|account|user|login|auth|credential|secret|token)/i;

/** 判断文件是否像文本(可解码为 UTF-8 且 NUL 占比低) */
export function looksText(buf: Buffer): boolean {
  if (buf.length === 0) return true;
  const sample = buf.subarray(0, Math.min(buf.length, 4096));
  let nul = 0;
  for (const b of sample) if (b === 0) nul++;
  if (nul / sample.length > 0.02) return false;
  try {
    const decoded = sample.toString('utf8');
    return !decoded.includes('�') || decoded.length > 0;
  } catch {
    return false;
  }
}

function isLikelyTextFile(path: string, buf: Buffer): boolean {
  if (TEXT_EXT.test(path)) return true;
  return looksText(buf);
}

const PEM_PATTERNS: Array<{ re: RegExp; severity: Severity; title: string; advice: string }> = [
  {
    re: /-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/,
    severity: 'critical',
    title: '文件中包含私钥',
    advice: '私钥不应随固件分发;移到安全存储并轮换该密钥对',
  },
  {
    re: /-----BEGIN CERTIFICATE-----/,
    severity: 'medium',
    title: '文件中包含 X.509 证书',
    advice: '检查证书有效期与颁发者;自签名证书在生产环境应替换',
  },
  {
    re: /ssh-(rsa|ed25519|dss) [A-Za-z0-9+/=]+/,
    severity: 'medium',
    title: '文件中包含 SSH 公钥(authorized_keys 类)',
    advice: '确认该公钥是否为厂商后门账号,不必要则移除',
  },
];

const SECRET_PATTERNS: Array<{ re: RegExp; severity: Severity; title: string; advice: string }> = [
  {
    re: /\b(password|passwd|pwd|admin_password|login_password|auth_key|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*['"]?([^\s'";,#]{3,})/i,
    severity: 'high',
    title: '疑似硬编码口令/密钥',
    advice: '改为首次启动强制修改,或使用安全存储,不要明文写在配置里',
  },
  {
    re: /\b(user(name)?|login|account)\s*[:=]\s*['"]?(root|admin|administrator)\b/i,
    severity: 'medium',
    title: '硬编码特权账号',
    advice: '默认特权账号应强制改名或首启改密',
  },
  {
    re: /\b(enable|telnet|ftp|upnp|wps|dmz)\s*[:=]\s*('?"?1'?"?|on|yes|true|enable)\b/i,
    severity: 'low',
    title: '默认开启的高风险功能',
    advice: 'Telnet/FTP/UPnP/WPS/DMZ 等功能默认应关闭',
  },
  {
    re: /\bPermitRootLogin\s+yes\b/,
    severity: 'high',
    title: 'SSH 允许 root 直接登录',
    advice: '设置 PermitRootLogin no 或 prohibit-password',
  },
  {
    re: /\bPermitEmptyPasswords\s+yes\b/,
    severity: 'critical',
    title: 'SSH 允许空口令登录',
    advice: '必须设置 PermitEmptyPasswords no',
  },
  {
    re: /\b(0\.0\.0\.0|::)\s+(\/admin|\/api|\/cgi-bin)/,
    severity: 'medium',
    title: '管理接口监听全网卡',
    advice: '管理面只应绑定内网/回环地址',
  },
];

const WEAK_CONFIG_LINES: Array<{ re: RegExp; severity: Severity; reason: string }> = [
  { re: /\btelnetd?\b/, severity: 'high', reason: 'Telnet 明文传输凭证,应改用 SSH' },
  { re: /\b(vsftpd|ftpd|proftpd|pure-ftpd)\b.*(-w|anon|anonymous)/, severity: 'high', reason: 'FTP 匿名/明文服务' },
  { re: /\bhttpd?\b.*(-S|ssl)/, severity: 'info', reason: '启用 HTTPS(确认证书强度)' },
  { re: /\bchmod\s+(-R\s+)?777\b/, severity: 'high', reason: '递归 777 权限,任意用户可写' },
  { re: /\bchmod\s+(-R\s+)?666\b/, severity: 'medium', reason: '全局可写文件' },
  { re: /\b(iptables|ip6tables)\s+-F\b/, severity: 'medium', reason: '启动脚本清空防火墙规则' },
  { re: /\becho\s+0?\s*>\s*\/proc\/sys\/(net\/ipv4\/)?(kernel\/)?(kptr_restrict|dmesg_restrict)/, severity: 'low', reason: '关闭内核地址保护' },
  { re: /\b(nc|netcat)\s+-l\b.*(-e\s+\/bin\/sh)/, severity: 'critical', reason: '监听型反向 shell' },
  { re: /\bwget\b.*\|\s*sh\b/, severity: 'critical', reason: '下载即执行的远程脚本,供应链风险' },
  { re: /\bupnpd?\b/, severity: 'medium', reason: 'UPnP 默认开启,可能被利用打洞' },
  { re: /\bminissdpd?\b/, severity: 'low', reason: 'SSDP/UPnP 发现服务暴露' },
];

const PORT_HINTS: Array<{ re: RegExp; name: string; port: number; proto: 'tcp' | 'udp'; risky: boolean; reason?: string }> = [
  { re: /\btelnetd?\b/, name: 'Telnet', port: 23, proto: 'tcp', risky: true, reason: '明文远程登录' },
  { re: /\b(dropbear|sshd)\b/, name: 'SSH', port: 22, proto: 'tcp', risky: false },
  { re: /\b(vsftpd|ftpd|proftpd)\b/, name: 'FTP', port: 21, proto: 'tcp', risky: true, reason: '明文文件传输' },
  { re: /\bhttpd?\b/, name: 'HTTP 管理', port: 80, proto: 'tcp', risky: true, reason: 'Web 管理走明文 HTTP' },
  { re: /\b(uhttpd|lighttpd|nginx)\b.*\b443\b/, name: 'HTTPS 管理', port: 443, proto: 'tcp', risky: false },
  { re: /\bupnpd?\b/, name: 'UPnP', port: 5000, proto: 'tcp', risky: true, reason: 'UPnP 自动端口映射' },
  { re: /\b(snmpd)\b/, name: 'SNMP', port: 161, proto: 'udp', risky: true, reason: '检查 community 是否为 public/private 默认值' },
  { re: /\b(dnsmasq)\b/, name: 'DNS/DHCP', port: 53, proto: 'udp', risky: false },
  { re: /\bminidlna\b/, name: 'DLNA', port: 8200, proto: 'tcp', risky: false },
];

export interface RuleOutput {
  findings: Finding[];
  services: ServiceEntry[];
  startupConfigs: StartupConfig[];
}

/** 主入口:对所有可读文本文件跑规则 */
export function runRules(files: RuleFile[], extraWords: string[] = []): RuleOutput {
  const findings: Finding[] = [];
  const services: ServiceEntry[] = [];
  const startupConfigs: StartupConfig[] = [];
  const words = [...BUILTIN_WORDLIST, ...extraWords.filter(Boolean)];
  const serviceSeen = new Set<string>();

  for (const f of files) {
    const text = f.content.toString('utf8');
    const lines = text.split(/\r?\n/);
    const isStartup = STARTUP_PATH.test(f.path) || /(rcS|init|startup|boot)/i.test(f.path);

    // 1. PEM 密钥/证书
    for (const p of PEM_PATTERNS) {
      const m = text.match(p.re);
      if (m) {
        const line = lines.findIndex((l) => p.re.test(l)) + 1;
        findings.push({
          id: nextId(),
          severity: p.severity,
          category: '私钥与证书',
          title: p.title,
          path: f.path,
          line: line || undefined,
          evidence: m[0].slice(0, 80),
          advice: p.advice,
        });
      }
    }

    // 2. shadow 弱哈希
    if (/(^|\/)shadow$/.test(f.path)) {
      lines.forEach((line, idx) => {
        const parts = line.split(':');
        if (parts.length < 2 || !parts[0] || parts[0].startsWith('#')) return;
        const hash = parts[1];
        if (!hash || hash === '*' || hash === '!' || hash === '!!') return;
        const kind = identifyHash(hash);
        if (hash === '') {
          findings.push(mk('critical', '弱哈希', `账号 ${parts[0]} 为空口令`, f.path, idx + 1, line, '为该账号设置强口令'));
          return;
        }
        if (kind === 'des') {
          findings.push(mk('high', '弱哈希', `账号 ${parts[0]} 使用遗留 DES crypt(13 位),已不安全`, f.path, idx + 1, line, '升级为 SHA-512 crypt ($6$)'));
          return;
        }
        if (kind === 'unknown') return;
        const cracked = crackHash(hash, words);
        findings.push(
          mk(
            cracked ? 'critical' : 'medium',
            cracked ? '弱口令' : '弱哈希',
            cracked
              ? `账号 ${parts[0]} 口令被字典破解:${cracked}`
              : `账号 ${parts[0]} 使用可离线破解的 ${kind} 哈希(字典未命中)`,
            f.path,
            idx + 1,
            line,
            '使用强随机口令并迁移到 SHA-512/yescrypt',
            undefined,
            !!cracked
          )
        );
      });
    }

    // 3. 逐行通用规则(只对文本/敏感文件跑,避免二进制噪声)
    if (isLikelyTextFile(f.path, f.content)) {
      lines.forEach((line, idx) => {
        if (!line.trim() || line.trim().startsWith('#')) return;
        for (const p of SECRET_PATTERNS) {
          const m = line.match(p.re);
          if (m) {
            const evidence = maskSecret(line);
            findings.push(mk(p.severity, '硬编码口令', `${p.title}:${m[1] ?? ''}`, f.path, idx + 1, evidence, p.advice));
          }
        }
        if (isStartup) {
          for (const w of WEAK_CONFIG_LINES) {
            if (w.re.test(line)) {
              startupConfigs.push({ file: f.path, line: idx + 1, raw: line.slice(0, 160), risky: true, reason: w.reason });
              findings.push(mk(w.severity, '危险配置', w.reason, f.path, idx + 1, line.slice(0, 160), '移除或替换该启动配置项'));
            }
          }
          for (const hint of PORT_HINTS) {
            if (hint.re.test(line)) {
              const key = `${hint.name}:${hint.port}`;
              if (!serviceSeen.has(key)) {
                serviceSeen.add(key);
                services.push({ name: hint.name, port: hint.port, proto: hint.proto, source: f.path, risky: hint.risky, reason: hint.reason });
              }
            }
          }
        }
      });
    }

    // 4. 额外:配置文件里的默认 community / 出厂账号文件
    if (/snmp/i.test(f.path) && /\b(public|private)\b/.test(text)) {
      const idx = lines.findIndex((l) => /\b(public|private)\b/.test(l));
      findings.push(mk('high', '危险配置', 'SNMP 使用默认 community 字符串', f.path, idx + 1, lines[idx], '更换自定义 community 并限制源地址'));
    }
    if (SENSITIVE_NAME.test(f.path) && isLikelyTextFile(f.path, f.content)) {
      lines.forEach((line, idx) => {
        // admin:admin 形式的出厂凭据
        const m = line.match(/^\s*(root|admin|support|guest)\s*[:|]\s*([A-Za-z0-9@_.!#$%^&*-]{3,})\s*$/);
        if (m) {
          const pw = m[2];
          const hit = words.includes(pw) ? pw : null;
          findings.push(
            mk(hit ? 'critical' : 'high', hit ? '弱口令' : '硬编码口令',
              hit ? `出厂默认账号 ${m[1]} / ${pw}(字典命中)` : `出厂账号 ${m[1]} 带明文口令`,
              f.path, idx + 1, maskSecret(line), '出厂默认凭据应强制首启修改', undefined, !!hit)
          );
        }
      });
    }
  }

  return { findings: dedupe(findings), services, startupConfigs };
}

function mk(
  severity: Severity,
  category: Finding['category'],
  title: string,
  path?: string,
  line?: number,
  evidence?: string,
  advice?: string,
  refs?: string[],
  cracked = false
): Finding {
  return { id: nextId(), severity, category, title, path, line, evidence: evidence?.slice(0, 200), advice, refs, cracked };
}

function maskSecret(line: string): string {
  return line.replace(/(password|passwd|pwd|secret|token|key)(\s*[:=]\s*['"]?)([^\s'";,#]+)/i, (_m, k, sep) => `${k}${sep}********`);
}

function dedupe(list: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of list) {
    const key = `${f.category}|${f.title}|${f.path ?? ''}|${f.line ?? 0}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}
