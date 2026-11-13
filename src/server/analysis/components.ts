// 组件识别:busybox / openssl / dropbear 版本提取 + 离线漏洞库比对
import type { ComponentInfo, FsNode } from '../../shared/types.js';
import { extractStrings } from '../../shared/magic.js';
import { matchVulns } from './vulndb.js';

interface VersionHit {
  name: string;
  version: string;
  path: string;
}

const COMPONENT_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: 'busybox', re: /BusyBox\s+v?(\d+\.\d+(?:\.\d+)?)/i },
  { name: 'dropbear', re: /Dropbear\s+(?:SSH\s+)?v?(\d{4}\.\d{2}(?:-[a-z0-9]+)?|\d+\.\d+)/i },
  { name: 'openssl', re: /OpenSSL\s+(\d+\.\d+\.\d+[a-z0-9-]*)/i },
];

/** 文件名/路径层面的识别(无内容 blob 时仍能给出线索) */
function detectByName(node: FsNode): VersionHit | null {
  const base = node.path.split('/').pop()?.toLowerCase() ?? '';
  if (base === 'busybox' || base.startsWith('busybox')) return { name: 'busybox', version: '未知(仅文件名)', path: node.path };
  if (base === 'dropbear' || base === 'dropbearmulti') return { name: 'dropbear', version: '未知(仅文件名)', path: node.path };
  if (base === 'openssl' || /^lib(ssl|crypto)/.test(base)) return { name: 'openssl', version: '未知(仅文件名)', path: node.path };
  return null;
}

export function identifyComponents(files: Array<{ path: string; content: Buffer | null; node: FsNode }>): ComponentInfo[] {
  const hits = new Map<string, VersionHit>();

  for (const f of files) {
    const nameHit = detectByName(f.node);
    if (nameHit && !hits.has(nameHit.name)) hits.set(nameHit.name, nameHit);

    if (!f.content || f.content.length === 0) continue;
    // 大文件采样前 2MB + 字符串扫描,控制耗时
    const sample = f.content.length > 2 * 1024 * 1024 ? f.content.subarray(0, 2 * 1024 * 1024) : f.content;
    const strings = extractStrings(sample, 5, 3000);
    const joined = strings.join('\n');
    for (const p of COMPONENT_PATTERNS) {
      const m = joined.match(p.re);
      if (m) {
        const existing = hits.get(p.name);
        // 真实版本号优先于"仅文件名"
        if (!existing || existing.version.startsWith('未知')) {
          hits.set(p.name, { name: p.name, version: m[1], path: f.path });
        }
      }
    }
  }

  const out: ComponentInfo[] = [];
  for (const hit of hits.values()) {
    out.push({
      name: hit.name,
      version: hit.version,
      path: hit.path,
      vulns: hit.version.startsWith('未知') ? [] : matchVulns(hit.name, hit.version),
    });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}
