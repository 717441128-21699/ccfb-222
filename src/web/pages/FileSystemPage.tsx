import { useMemo, useState } from 'react';
import { useSelectedFull } from '../store';
import { api } from '../api';
import { PageHeader, humanSize, modeText, EmptyHint } from '../components/ui';
import type { FsNode } from '../../shared/types';

interface RawData {
  size: number;
  isText: boolean;
  text: string | null;
  hex: { offset: string; hex: string; ascii: string }[];
}

export function FileSystemPage() {
  const { meta, loading } = useSelectedFull();
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<FsNode | null>(null);
  const [raw, setRaw] = useState<RawData | null>(null);
  const [tab, setTab] = useState<'text' | 'hex'>('text');
  const [rawLoading, setRawLoading] = useState(false);
  const [rawError, setRawError] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const tree = meta?.analysis?.tree ?? null;

  const matches = useMemo(() => {
    if (!tree || !query.trim()) return null;
    const q = query.toLowerCase();
    const out: FsNode[] = [];
    walk(tree, (n) => {
      if (n.name.toLowerCase().includes(q) || n.path.toLowerCase().includes(q)) out.push(n);
    });
    return out.slice(0, 200);
  }, [tree, query]);

  const openNode = async (n: FsNode) => {
    setSelected(n);
    setRaw(null);
    setRawError(null);
    if (n.type !== 'file' || !n.blob) return;
    setRawLoading(true);
    try {
      const data = await api.raw(meta!.id, n.blob);
      setRaw(data);
      setTab(data.isText ? 'text' : 'hex');
    } catch (e) {
      setRawError((e as Error).message);
    } finally {
      setRawLoading(false);
    }
  };

  const toggle = (id: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  if (loading && !meta) {
    return (
      <div>
        <PageHeader title="文件系统" />
        <p className="mut"><span className="spinner" /> 加载…</p>
      </div>
    );
  }
  if (!meta) {
    return (
      <div>
        <PageHeader title="文件系统" />
        <EmptyHint text="请先在「固件库」选择固件。" />
      </div>
    );
  }
  if (!tree) {
    return (
      <div>
        <PageHeader title="文件系统" sub={meta.originalName} />
        <EmptyHint text="未展开出文件系统(裸内核、截断镜像或真实第三方 FS)。可在「结构解析」查看超级块与告警。" />
      </div>
    );
  }

  return (
    <div>
      <PageHeader
        title="文件系统"
        sub={`${meta.originalName} · ${meta.analysis?.stats.fileCount ?? 0} 个文件 · ${meta.analysis?.stats.dirCount ?? 0} 个目录`}
      />
      <div className="fs-layout">
        <div>
          <input
            className="search-box"
            placeholder="搜索文件名或路径,如 shadow、rcS、busybox"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="fs-tree">
            {matches ? (
              <SearchResults results={matches} onPick={(n) => void openNode(n)} selected={selected} />
            ) : (
              <TreeNode node={tree} depth={0} collapsed={collapsed} toggle={toggle} onPick={(n) => void openNode(n)} selected={selected} />
            )}
          </div>
        </div>

        <div className="viewer">
          {!selected ? (
            <EmptyHint text="在左侧选择文件查看内容;目录可展开,符号链接显示目标。" />
          ) : (
            <>
              <div className="flex-between mb">
                <div>
                  <strong className="mono">{selected.path}</strong>
                  <div className="small mut mt">
                    {selected.type === 'symlink'
                      ? `符号链接 → ${selected.linkTarget}`
                      : `${humanSize(selected.size)} · 权限 ${modeText(selected.mode)} · uid=${selected.uid} gid=${selected.gid}${selected.truncated ? ' · 内容超过抽取上限' : ''}`}
                  </div>
                </div>
              </div>

              {selected.elf && <ElfPanel elf={selected.elf} />}

              {selected.type === 'file' && !selected.blob && (
                <div className="warn">该文件未抽取内容(超过 256KB 上限或镜像截断),仅展示元数据。</div>
              )}
              {rawLoading && <p className="mut"><span className="spinner" /> 读取内容…</p>}
              {rawError && <div className="err">读取失败:{rawError}</div>}
              {raw && (
                <>
                  <div className="tabs">
                    {raw.isText && <button className={`tab ${tab === 'text' ? 'active' : ''}`} onClick={() => setTab('text')}>文本视图</button>}
                    <button className={`tab ${tab === 'hex' ? 'active' : ''}`} onClick={() => setTab('hex')}>十六进制</button>
                  </div>
                  {tab === 'text' && raw.text != null ? (
                    <pre className="text-view">{raw.text}</pre>
                  ) : (
                    <div style={{ maxHeight: '60vh', overflow: 'auto' }}>
                      <table className="hex mono">
                        <tbody>
                          {raw.hex.map((r, i) => (
                            <tr key={i}>
                              <td className="mut">{r.offset}</td>
                              <td>{r.hex}</td>
                              <td className="mut">{r.ascii}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function TreeNode(props: {
  node: FsNode;
  depth: number;
  collapsed: Set<string>;
  toggle: (id: string) => void;
  onPick: (n: FsNode) => void;
  selected: FsNode | null;
}) {
  const { node, depth, collapsed, toggle, onPick, selected } = props;
  const hasKids = node.type === 'dir' && node.children?.length;
  const isCollapsed = collapsed.has(node.id);
  return (
    <div>
      <div
        className={`tree-row ${selected?.id === node.id ? 'selected' : ''}`}
        style={{ paddingLeft: 8 + depth * 14 }}
        onClick={() => (node.type === 'dir' ? toggle(node.id) : onPick(node))}
      >
        <span className="caret">{hasKids ? (isCollapsed ? '▶' : '▼') : node.type === 'dir' ? ' ' : ''}</span>
        <span>{node.type === 'dir' ? '📁' : node.type === 'symlink' ? '🔗' : node.elf ? '🧩' : '📄'}</span>
        <span>{node.name || '/'}</span>
        {node.type === 'file' && <span className="small mut">{humanSize(node.size)}</span>}
      </div>
      {hasKids && !isCollapsed && node.children!.map((c) => (
        <TreeNode key={c.id} {...props} node={c} depth={depth + 1} />
      ))}
    </div>
  );
}

function SearchResults({ results, onPick, selected }: { results: FsNode[]; onPick: (n: FsNode) => void; selected: FsNode | null }) {
  if (!results.length) return <EmptyHint text="没有匹配的文件。" />;
  return (
    <div>
      <div className="small mut mb">{results.length} 个匹配(最多显示 200)</div>
      {results.map((n) => (
        <div key={n.id} className={`tree-row ${selected?.id === n.id ? 'selected' : ''}`} onClick={() => onPick(n)}>
          <span>{n.type === 'dir' ? '📁' : n.type === 'symlink' ? '🔗' : '📄'}</span>
          <span className="mono small">{n.path}</span>
        </div>
      ))}
    </div>
  );
}

function ElfPanel({ elf }: { elf: NonNullable<FsNode['elf']> }) {
  return (
    <div className="card" style={{ background: 'var(--bg-2)', marginBottom: 14 }}>
      <h3>ELF 信息</h3>
      <div className="kv">
        <span className="k">架构</span><strong>{elf.machine}</strong>
        <span className="k">位数/字节序</span><span>{elf.class} · {elf.endian}</span>
        <span className="k">类型</span><span>{elf.type}</span>
        <span className="k">入口地址</span><span className="mono">{elf.entry}</span>
        <span className="k">链接方式</span><span>{elf.staticLinked ? '静态链接或已 strip(无动态符号)' : '动态链接'}</span>
        <span className="k">导入函数</span>
        <span>
          {elf.imports.length ? (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {elf.imports.map((s) => <span key={s} className="tag mono">{s}</span>)}
            </div>
          ) : (
            <span className="mut">未提取到动态导入(可能 strip)</span>
          )}
        </span>
      </div>
    </div>
  );
}

function walk(n: FsNode, fn: (n: FsNode) => void): void {
  fn(n);
  n.children?.forEach((c) => walk(c, fn));
}
