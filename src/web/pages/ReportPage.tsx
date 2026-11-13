import { useState } from 'react';
import { useFirmware, useSelectedFull } from '../store';
import { api } from '../api';
import { PageHeader, SeverityBadge, EmptyHint } from '../components/ui';
import type { DiffResult } from '../../shared/types';

export function ReportPage() {
  const { items, selectedId } = useFirmware();
  const { meta } = useSelectedFull();
  const [otherId, setOtherId] = useState('');
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const runDiff = async () => {
    if (!selectedId || !otherId) return;
    setBusy(true);
    setErr(null);
    try {
      setDiff(await api.diff(selectedId, otherId));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <PageHeader title="报告与版本对比" sub="导出独立 HTML 报告(内联样式、无外部依赖),或对比两个固件版本看补丁变化。" />

      <div className="card">
        <h3>HTML 报告</h3>
        {!meta ? (
          <EmptyHint text="请先在「固件库」选择固件。" />
        ) : (
          <div className="flex-between">
            <div>
              <strong>{meta.originalName}</strong>
              <div className="small mut">
                {meta.analysis?.findings.length ?? 0} 项发现 · {meta.analysis?.components.length ?? 0} 个组件 · 报告可离线打开或直接发送
              </div>
            </div>
            <a className="btn" href={api.reportUrl(meta.id)} target="_blank" rel="noreferrer">
              导出 HTML 报告
            </a>
          </div>
        )}
      </div>

      <div className="card">
        <h3>版本差异对比</h3>
        {items.length < 2 ? (
          <EmptyHint text="至少需要两个固件才能对比,可导入测试样本获得 router-v1 / router-v2。" />
        ) : (
          <>
            <div className="flex mb">
              <div className="grow">
                <div className="small mut mb">旧版本(A)</div>
                <select className="grow" style={{ width: '100%' }} value={selectedId ?? ''} disabled>
                  {items.map((m) => <option key={m.id} value={m.id}>{m.originalName}</option>)}
                </select>
              </div>
              <div className="grow">
                <div className="small mut mb">新版本(B)</div>
                <select className="grow" style={{ width: '100%' }} value={otherId} onChange={(e) => setOtherId(e.target.value)}>
                  <option value="">选择对比固件…</option>
                  {items.filter((m) => m.id !== selectedId).map((m) => (
                    <option key={m.id} value={m.id}>{m.originalName}</option>
                  ))}
                </select>
              </div>
              <button className="btn" style={{ marginTop: 18 }} disabled={!otherId || busy} onClick={() => void runDiff()}>
                {busy ? '对比中…' : '开始对比'}
              </button>
            </div>
            {err && <div className="err">{err}</div>}
            {diff && <DiffView diff={diff} />}
          </>
        )}
      </div>
    </div>
  );
}

function DiffView({ diff }: { diff: DiffResult }) {
  const added = diff.entries.filter((e) => e.change === 'added');
  const removed = diff.entries.filter((e) => e.change === 'removed');
  const modified = diff.entries.filter((e) => e.change === 'modified');
  return (
    <div>
      <div className="small mut mb">
        {diff.aName} → {diff.bName}
      </div>
      <div className="stat-grid mb">
        <div className="stat"><div className="n" style={{ color: 'var(--ok)' }}>{added.length}</div><div className="l">新增文件</div></div>
        <div className="stat"><div className="n" style={{ color: 'var(--crit)' }}>{removed.length}</div><div className="l">删除文件</div></div>
        <div className="stat"><div className="n" style={{ color: 'var(--med)' }}>{modified.length}</div><div className="l">修改文件</div></div>
        <div className="stat">
          <div className="n" style={{ color: 'var(--high)' }}>{diff.findingsOnlyInA.length - diff.findingsOnlyInB.length >= 0 ? diff.findingsOnlyInB.length : 0}</div>
          <div className="l">新增风险</div>
        </div>
      </div>

      <table className="mb">
        <thead><tr><th>变化</th><th>路径</th><th>说明</th></tr></thead>
        <tbody>
          {diff.entries.map((e, i) => (
            <tr key={i}>
              <td className="nowrap">
                <span className={`badge ${e.change === 'added' ? 'ok' : e.change === 'removed' ? 'critical' : 'medium'}`}>
                  {e.change === 'added' ? '新增' : e.change === 'removed' ? '删除' : '修改'}
                </span>
              </td>
              <td className="mono">{e.path}</td>
              <td className="small mut">{e.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="fs-layout" style={{ gridTemplateColumns: '1fr 1fr' }}>
        <div>
          <h3 className="small">旧版本独有风险({diff.findingsOnlyInA.length})— 补丁可能已修复</h3>
          {diff.findingsOnlyInA.length === 0 && <EmptyHint text="无" />}
          {diff.findingsOnlyInA.map((f) => (
            <div key={f.id} className="warn" style={{ background: '#173d2c', borderColor: '#256b4a', color: 'var(--ok)' }}>
              <SeverityBadge severity={f.severity} /> <strong>{f.title}</strong>
              <div className="small mono mut">{f.path}</div>
            </div>
          ))}
        </div>
        <div>
          <h3 className="small">新版本新增风险({diff.findingsOnlyInB.length})— 补丁引入/残留</h3>
          {diff.findingsOnlyInB.length === 0 && <EmptyHint text="无新增风险" />}
          {diff.findingsOnlyInB.map((f) => (
            <div key={f.id} className="err">
              <SeverityBadge severity={f.severity} /> <strong>{f.title}</strong>
              <div className="small mono mut">{f.path}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
