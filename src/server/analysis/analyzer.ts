// 分析编排:结构扫描 → 压缩段解压 → 文件系统展开 → ELF/组件/规则 → 汇总
import type { AnalysisResult, FsNode, Segment } from '../../shared/types.js';
import { scanImage, decompressSegments } from './scanner.js';
import { extractFs, walkTree, type ExtractedFs } from './packed-fs.js';
import { parseElf } from './elf.js';
import { runRules, looksText, type RuleFile } from './findings.js';
import { identifyComponents } from './components.js';
import { saveBlob } from '../storage.js';
import { MAGICS, findMagic } from '../../shared/magic.js';

export interface AnalyzeOptions {
  extraWords?: string[];
  maxBlobSize?: number;
}

export async function analyze(buf: Buffer, opts: AnalyzeOptions = {}): Promise<AnalysisResult> {
  const warnings: string[] = [];
  const stats = { fileCount: 0, dirCount: 0, extractedBlobs: 0, skippedLarge: 0 };

  // 1. 结构扫描
  const segments = scanImage(buf);
  collectSegmentWarnings(segments, warnings);

  // 2. 解压压缩段(失败只挂错误,不抛出)
  const decompressed = await decompressSegments(buf, segments);

  // 3. 找文件系统:先在原始镜像找,再在各解压产物里找
  let extracted: ExtractedFs | null = null;
  const candidates: Array<{ name: string; data: Buffer }> = [{ name: '原始镜像', data: buf }];
  for (const [key, data] of decompressed) candidates.push({ name: `解压段 ${key}`, data });

  for (const c of candidates) {
    try {
      const r = extractFs(c.data, opts.maxBlobSize ?? 256 * 1024);
      if (r.entries.length > 0 || r.outerSuper) {
        extracted = r;
        if (c.name !== '原始镜像') {
          warnings.push(`文件系统在 ${c.name} 中找到并展开`);
        }
        break;
      }
    } catch {
      /* 该候选无 FS,继续 */
    }
  }

  let tree: FsNode | null = null;
  if (extracted) {
    tree = extracted.root;
    warnings.push(...extracted.warnings);
    if (extracted.unsupported) warnings.push(extracted.unsupported);
    // blob 落盘 + 统计 + ELF 解析
    const blobs = new Map<string, Buffer>();
    walkTree(tree, (n) => {
      if (n.type === 'dir') stats.dirCount++;
      if (n.type === 'file') stats.fileCount++;
    });
    // 把 entries 的内容按 blob 名落盘
    for (const e of extracted.entries) {
      if (e.type === 'file' && e.data && e.data.length <= (opts.maxBlobSize ?? 256 * 1024)) {
        const hash = saveBlob(e.data);
        blobs.set(e.path, e.data);
        const node = findNode(tree!, e.path);
        if (node) {
          node.blob = hash;
          stats.extractedBlobs++;
          if (e.data.length > 0 && e.data.subarray(0, 4).equals(MAGICS.elf)) {
            node.elf = parseElf(e.data) ?? undefined;
          }
        }
      } else if (e.type === 'file' && e.data && e.data.length > (opts.maxBlobSize ?? 256 * 1024)) {
        stats.skippedLarge++;
        const node = findNode(tree!, e.path);
        if (node) node.truncated = true;
      }
    }

    // 4. 规则引擎 + 组件识别
    const ruleFiles: RuleFile[] = [];
    const compFiles: Array<{ path: string; content: Buffer | null; node: FsNode }> = [];
    walkTree(tree, (n) => {
      if (n.type !== 'file' || n.truncated) {
        if (n.type === 'file') compFiles.push({ path: n.path, content: null, node: n });
        return;
      }
      const data = blobs.get(n.path);
      if (!data) return;
      compFiles.push({ path: n.path, content: data, node: n });
      if (looksText(data)) ruleFiles.push({ path: n.path, content: data, node: n });
    });

    const ruleOut = runRules(ruleFiles, opts.extraWords);
    const components = identifyComponents(compFiles);

    // 漏洞提升为 finding
    const vulnFindings = components.flatMap((c) =>
      c.vulns.map((v) => ({
        id: `V-${v.cve}`,
        severity: v.severity,
        category: '漏洞' as const,
        title: `${c.name} ${c.version} 命中 ${v.cve}`,
        path: c.path,
        evidence: v.title,
        advice: `升级 ${c.name} 到 ${v.affected.replace('<', '≥')} 之后的版本`,
        refs: [v.cve],
      }))
    );

    // 组件汇总 finding(无漏洞也提示版本过老线索)
    const compFindings = components
      .filter((c) => c.vulns.length === 0 && !c.version.startsWith('未知'))
      .map((c) => ({
        id: `C-${c.name}`,
        severity: 'info' as const,
        category: '组件' as const,
        title: `识别到 ${c.name} ${c.version}(离线库未命中已知漏洞)`,
        path: c.path,
      }));

    return {
      segments,
      tree,
      findings: [...ruleOut.findings, ...vulnFindings, ...compFindings],
      components,
      services: ruleOut.services,
      startupConfigs: ruleOut.startupConfigs,
      warnings,
      stats,
    };
  }

  // 没有文件系统:仍返回结构与告警
  return {
    segments,
    tree: null,
    findings: [],
    components: [],
    services: [],
    startupConfigs: [],
    warnings: [...warnings, '未在镜像或解压产物中发现可展开的文件系统(可能为裸内核或镜像被截断)'],
    stats,
  };
}

function collectSegmentWarnings(segs: Segment[], out: string[]): void {
  for (const s of segs) {
    s.warnings?.forEach((w) => out.push(`[${s.type}@${s.offset}] ${w}`));
    if (s.error) out.push(`[${s.type}@${s.offset}] 错误:${s.error}`);
    if (s.children) collectSegmentWarnings(s.children, out);
  }
}

function findNode(root: FsNode, path: string): FsNode | null {
  let found: FsNode | null = null;
  walkTree(root, (n) => {
    if (n.path === path) found = n;
  });
  return found;
}

/** 供报告/搜索用:全镜像魔数命中列表(确认 squashfs 等真实魔数) */
export function listEmbeddedMagics(buf: Buffer): Record<string, number[]> {
  return {
    squashfs: findMagic(buf, MAGICS.squashfs),
    cramfs: findMagic(buf, MAGICS.cramfs),
    gzip: findMagic(buf, MAGICS.gzip),
    xz: findMagic(buf, MAGICS.xz),
    uImage: findMagic(buf, MAGICS.uImage),
    trx: findMagic(buf, MAGICS.trx),
  };
}
