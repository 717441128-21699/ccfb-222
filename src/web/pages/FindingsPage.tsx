import { useMemo, useState } from 'react';
import { useSelectedFull, useFirmware } from '../store';
import { api } from '../api';
import { PageHeader, SeverityBadge, EmptyHint } from '../components/ui';
import type { Finding, Severity } from '../../shared/types';

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function FindingsPage() {
  const { meta, reload } = useSelectedFull();
  const { refresh } = useFirmware();
  const [sevFilter, setSevFilter] = useState<Severity | 'all'>('all');
  const [catFilter, setCatFilter] = useState<string>('all');
  const [keyword, setKeyword] = useState('');
  const [words, setWords] = useState('');
  const [running, setRunning] = useState(false);

  const a = meta?.analysis;
  const findings = a?.findings ?? [];

  const categories = useMemo(() => [...new Set(findings.map((f) => f.category))], [findings]);
  const counts = useMemo(() => {
    const c: Record<string, number> = { all: findings.length };
    for (const s of SEV_ORDER) c[s] = findings.filter((f) => f.severity === s).length;
    return c;
  }, [findings]);

  const filtered = useMemo(() => {
    return findings
      .filter((f) => (sevFilter === 'all' ? true : f.severity === sevFilter))
      .filter((f) => (catFilter === 'all' ? true : f.category === catFilter))
      .filter((f) => {
        if (!keyword.trim()) return true;
        const q = keyword.toLowerCase();
        return [f.title, f.path, f.evidence, f.advice].some((x) => x?.toLowerCase().includes(q));
      })
      .sort((x, y) => SEV_ORDER.indexOf(x.severity) - SEV_ORDER.indexOf(y.severity));
  }, [findings, sevFilter, catFilter, keyword]);

  const rerunDict = async () => {
    if (!meta) return;
    setRunning(true);
    try {
      await api.reanalyze(meta.id, words.split(/[\s,;]+/).filter(Boolean));
      await reload();
      await refresh();
      alert('已用追加字典重新分析完成');
    } catch (e) {
      alert(`重新分析失败:${(e as Error).message}`);
    } finally {
      setRunning(false);
    }
  };

  if (!meta) {
    return (
      <div>
        <PageHeader title="风险发现" />
        <EmptyHint text="请先在「固件库」选择固件。" />
      </div>
    );
  }

  return (
    <div>
      <PageHeader title="风险发现" sub={`${meta.originalName} · 共 ${findings.length} 项发现`} />

      <div className="stat-grid mb">
        <div className="stat"><div className="n" style={{ color: 'var(--crit)' }}>{counts.critical ?? 0}</div><div className="l">严重</div></div>
        <div className="stat"><div className="n" style={{ color: 'var(--high)' }}>{counts.high ?? 0}</div><div className="l">高危</div></div>
        <div className="stat"><div className="n" style={{ color: 'var(--med)' }}>{counts.medium ?? 0}</div><div className="l">中危</div></div>
        <div className="stat"><div className="n" style={{ color: 'var(--low)' }}>{counts.low ?? 0}</div><div className="l">低危</div></div>
        <div className="stat"><div className="n">{counts.info ?? 0}</div><div className="l">提示</div></div>
      </div>

      <div className="card">
        <h3>自定义字典破解</h3>
        <p className="small mut" style={{ marginTop: -8 }}>
          内置 40 个常见弱口令(admin、123456、password123 等)。可追加企业专属词条,对 shadow 哈希重新跑字典。
        </p>
        <div className="flex">
          <input
            className="grow"
            type="text"
            placeholder="追加词条,空格/逗号分隔,如:acme2026 router-admin Q3!firmware"
            value={words}
            onChange={(e) => setWords(e.target.value)}
          />
          <button className="btn" disabled={running} onClick={() => void rerunDict()}>
            {running ? '破解中…' : '重新分析'}
          </button>
        </div>
      </div>

      <div className="card">
        <div className="flex-between mb">
          <div className="flex" style={{ flexWrap: 'wrap', gap: 8 }}>
            <FilterChip active={sevFilter === 'all'} onClick={() => setSevFilter('all')} label={`全部 ${counts.all ?? 0}`} />
            {SEV_ORDER.map((s) => (
              <FilterChip key={s} active={sevFilter === s} onClick={() => setSevFilter(s)} label={`${s} ${counts[s] ?? 0}`} />
            ))}
          </div>
          <div className="flex">
            <select value={catFilter} onChange={(e) => setCatFilter(e.target.value)}>
              <option value="all">全部分类</option>
              {categories.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
            <input type="text" placeholder="过滤关键字…" value={keyword} onChange={(e) => setKeyword(e.target.value)} />
          </div>
        </div>

        {filtered.length === 0 ? (
          <EmptyHint text="没有符合条件的发现。" />
        ) : (
          <table>
            <thead>
              <tr><th>等级</th><th>分类</th><th>问题</th><th>位置 / 证据</th><th>修复建议</th></tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <FindingRow key={f.id} f={f} />
              ))}
            </tbody>
          </table>
        )}
      </div>

      {a && a.components.length > 0 && (
        <div className="card">
          <h3>组件识别与离线漏洞比对</h3>
          <table>
            <thead><tr><th>组件</th><th>版本</th><th>路径</th><th>命中漏洞</th></tr></thead>
            <tbody>
              {a.components.map((c) => (
                <tr key={c.name + c.path}>
                  <td><strong>{c.name}</strong></td>
                  <td className="mono">{c.version}</td>
                  <td className="mono small">{c.path}</td>
                  <td>
                    {c.vulns.length === 0 ? (
                      <span className="badge ok">离线库未命中</span>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {c.vulns.map((v) => (
                          <div key={v.id} className="flex" style={{ gap: 8 }}>
                            <SeverityBadge severity={v.severity} />
                            <span className="mono small">{v.cve}</span>
                            <span className="small mut">{v.title}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {a && a.services.length > 0 && (
        <div className="card">
          <h3>启动服务与端口</h3>
          <table>
            <thead><tr><th>服务</th><th>端口</th><th>来源脚本</th><th>评估</th></tr></thead>
            <tbody>
              {a.services.map((s, i) => (
                <tr key={i} className={s.risky ? 'row-risk' : ''}>
                  <td>{s.name}</td>
                  <td className="mono">{s.port}/{s.proto}</td>
                  <td className="mono small">{s.source}</td>
                  <td>{s.risky ? <><span className="badge risk">风险</span> <span className="small">{s.reason}</span></> : <span className="badge ok">正常</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function FindingRow({ f }: { f: Finding }) {
  return (
    <tr>
      <td><SeverityBadge severity={f.severity} /></td>
      <td className="nowrap">{f.category}{f.cracked && <div className="small" style={{ color: 'var(--crit)' }}>字典已破解</div>}</td>
      <td style={{ minWidth: 220 }}>
        <strong>{f.title}</strong>
        {f.refs && <div className="small mono mut mt">{f.refs.join(' · ')}</div>}
      </td>
      <td style={{ minWidth: 240 }}>
        {f.path && <div className="mono small">{f.path}{f.line ? `:${f.line}` : ''}</div>}
        {f.evidence && <pre className="text-view small" style={{ maxHeight: 90, margin: '6px 0 0' }}>{f.evidence}</pre>}
      </td>
      <td className="small" style={{ minWidth: 180 }}>{f.advice ?? <span className="mut">—</span>}</td>
    </tr>
  );
}

function FilterChip({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button className={`tab ${active ? 'active' : ''}`} onClick={onClick}>{label}</button>
  );
}
