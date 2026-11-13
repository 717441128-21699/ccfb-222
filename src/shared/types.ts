// 前后端共享的数据类型定义

/** 镜像中识别出的段 / 分区类型 */
export type SegmentType =
  | 'uImage'
  | 'TRX'
  | 'squashfs'
  | 'cramfs'
  | 'lzma'
  | 'gzip'
  | 'xz'
  | 'kernel'
  | 'rootfs'
  | 'padding'
  | 'unknown';

export interface Segment {
  /** 段类型 */
  type: SegmentType;
  /** 在镜像中的字节偏移 */
  offset: number;
  /** 占用字节数(估算值会标记 estimated) */
  size: number;
  sizeIsEstimate?: boolean;
  /** 人类可读描述,如 "uImage header (MIPS, LZMA)" */
  label: string;
  /** 解析出的头字段 */
  details?: Record<string, string | number | boolean>;
  /** 压缩段解压后的大小 */
  uncompressedSize?: number;
  /** 嵌套子段(如 uImage 内部的压缩内核) */
  children?: Segment[];
  /** 解析告警(截断、校验错误等),前端黄色提示 */
  warnings?: string[];
  /** 解析错误,前端红色提示,不影响其它段 */
  error?: string;
}

export type FsNodeType = 'file' | 'dir' | 'symlink';

export interface FsNode {
  /** 节点 id,根为 "" */
  id: string;
  name: string;
  type: FsNodeType;
  path: string;
  size: number;
  mode: number;
  uid: number;
  gid: number;
  /** 符号链接目标 */
  linkTarget?: string;
  /** 数据来源:squashfs/cramfs/offset 等 */
  source?: string;
  /** 解压后内容在 data/blobs 下的文件名(仅小文件抽取) */
  blob?: string;
  /** 文件过大未抽取内容 */
  truncated?: boolean;
  /** ELF 信息缓存 */
  elf?: ElfInfo;
  children?: FsNode[];
}

export interface ElfInfo {
  class: '32位' | '64位';
  endian: '小端' | '大端';
  machine: string;
  type: string;
  entry: string;
  imports: string[];
  /** 是否静态链接(无动态段) */
  staticLinked: boolean;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  severity: Severity;
  category:
    | '硬编码口令'
    | '私钥与证书'
    | '弱哈希'
    | '危险配置'
    | '弱口令'
    | '漏洞'
    | '组件'
    | '其它';
  title: string;
  /** 命中文件路径 */
  path?: string;
  /** 命中行号(1 起) */
  line?: number;
  /** 证据片段 */
  evidence?: string;
  /** 修复建议 */
  advice?: string;
  /** 关联 CVE 等 */
  refs?: string[];
  /** 字典破解结果 */
  cracked?: boolean;
}

export interface ComponentInfo {
  name: 'busybox' | 'openssl' | 'dropbear' | string;
  version: string;
  path: string;
  /** 离线漏洞库命中 */
  vulns: VulnRecord[];
}

export interface VulnRecord {
  id: string;
  cve: string;
  component: string;
  /** 受影响版本范围,如 "<1.36.1" */
  affected: string;
  severity: Severity;
  title: string;
}

export interface ServiceEntry {
  name: string;
  port?: number;
  proto?: 'tcp' | 'udp';
  source: string;
  risky: boolean;
  reason?: string;
}

export interface StartupConfig {
  file: string;
  line: number;
  raw: string;
  risky: boolean;
  reason?: string;
}

export interface AnalysisResult {
  segments: Segment[];
  tree: FsNode | null;
  findings: Finding[];
  components: ComponentInfo[];
  services: ServiceEntry[];
  startupConfigs: StartupConfig[];
  /** 全局解析告警 */
  warnings: string[];
  stats: {
    fileCount: number;
    dirCount: number;
    extractedBlobs: number;
    skippedLarge: number;
  };
}

export interface FirmwareMeta {
  id: string;
  originalName: string;
  size: number;
  sha256: string;
  uploadedAt: string;
  /** 厂商/型号等可选备注 */
  note?: string;
  /** 分析是否完成 */
  analyzed: boolean;
  analysis?: AnalysisResult;
  /** 样本生成标记 */
  isSample?: boolean;
  /** 解析整体失败(镜像损坏)时仍保留库记录 */
  fatalError?: string;
}

export interface DiffEntry {
  path: string;
  change: 'added' | 'removed' | 'modified';
  detail: string;
}

export interface DiffResult {
  aId: string;
  bId: string;
  aName: string;
  bName: string;
  entries: DiffEntry[];
  findingsOnlyInA: Finding[];
  findingsOnlyInB: Finding[];
}
