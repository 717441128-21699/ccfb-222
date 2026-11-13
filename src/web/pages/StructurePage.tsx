import { useSelectedFull } from '../store';
import { PageHeader, humanSize, EmptyHint } from '../components/ui';
import type { Segment } from '../../shared/types';

const COLORS: Record<string, string> = {
  uImage: '#4f8cff',
  TRX: '#7c5cff',
  squashfs: '#5fd39a',
  cramfs: '#46b8a0',
  lzma: '#ffd76b',
  gzip: '#ffa26b',
  xz: '#ff9ad1',
  kernel: '#6bc3ff',
  rootfs: '#5fd39a',
  padding: '#2c3654',
  unknown: '#47537a',
};

export function StructurePage() {
  const { meta, loading } = useSelectedFull();
  if (loading && !meta) return <Loading title="结构解析" />;
  if (!meta) return <NoFirmware />;
  const a = meta.analysis;
  if (meta.fatalError) {
    return (
      <div>
        <PageHeader title="结构解析" sub={meta.originalName} />
        <div className="err">镜像解析整体失败,页面未崩溃:{meta.fatalError}</div>
      </div>
    );
  }
  if (!a) return <EmptyHint text="该固件还没有分析结果。" />;

  const total = meta.size || 1;
  const flat = flatten(a.segments);
  // 容器段(uImage/TRX)是概览,不参与按比例的字节布局条
  const layoutSegs = a.segments.filter((s) => s.type !== 'uImage' && s.type !== 'TRX');

  return (
    <div>
      <PageHeader title="结构解析" sub={`${meta.originalName} · ${humanSize(meta.size)} · 识别 ${flat.length} 个段`} />

      {a.warnings.length > 0 && (
        <div className="card">
          <h3>解析告警({a.warnings.length})</h3>
          {a.warnings.map((w, i) => (
            <div key={i} className="warn">{w}</div>
          ))}
        </div>
      )}

      <div className="card">
        <h3>分区布局(按字节偏移比例)</h3>
        <div className="part-bar">
          {layoutSegs.map((s, i) => (
            <div
              key={i}
              className="part-seg"
              title={`${s.label}\n偏移 0x${s.offset.toString(16).toUpperCase()} · ${humanSize(s.size)}`}
              style={{ width: `${(s.size / total) * 100}%`, background: COLORS[s.type] ?? '#47537a', color: s.type === 'padding' ? '#7d89a8' : '#0d1220' }}
            >
              <span>{s.type}</span>
            </div>
          ))}
        </div>
        <div className="part-legend">
          {[...new Set(flat.map((s) => s.type))].map((t) => (
            <div key={t} className="legend-item">
              <span className="legend-dot" style={{ background: COLORS[t] ?? '#47537a' }} />
              {t}
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h3>段明细</h3>
        <table>
          <thead>
            <tr>
              <th>#</th><th>类型</th><th>偏移</th><th>大小</th><th>解压后</th><th>说明</th><th>状态</th>
            </tr>
          </thead>
          <tbody>
            {flat.map((s, i) => (
              <tr key={i}>
                <td className="mut">{i + 1}</td>
                <td><span className="tag" style={{ borderColor: COLORS[s.type] }}>{s.type}</span></td>
                <td className="mono">0x{s.offset.toString(16).toUpperCase()}</td>
                <td className="nowrap">
                  {humanSize(s.size)}
                  {s.sizeIsEstimate && <span className="small mut" title="按镜像边界估算"> *</span>}
                </td>
                <td className="nowrap">{s.uncompressedSize ? humanSize(s.uncompressedSize) : <span className="mut">—</span>}</td>
                <td>{s.label}{s.details && <DetailGrid details={s.details} />}</td>
                <td>
                  {s.error ? (
                    <span className="badge high" title={s.error}>解压失败</span>
                  ) : s.warnings?.length ? (
                    <span className="badge medium" title={s.warnings.join('\n')}>{s.warnings.length} 告警</span>
                  ) : (
                    <span className="badge ok">正常</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="small mut mt">* 段未声明长度或镜像被截断时,大小按镜像边界估算。压缩段解压失败不会影响其它段与文件系统分析。</p>
      </div>
    </div>
  );
}

function DetailGrid({ details }: { details: Record<string, string | number | boolean> }) {
  const entries = Object.entries(details).filter(([k]) => k !== 'partOffsets' || details[k] !== '');
  if (!entries.length) return null;
  return (
    <div className="kv mt small">
      {entries.map(([k, v]) => (
        <div key={k} style={{ display: 'contents' }}>
          <span className="k">{k}</span>
          <span className="mono">{String(v)}</span>
        </div>
      ))}
    </div>
  );
}

function flatten(segs: Segment[], depth = 0): Array<Segment & { depth: number }> {
  const out: Array<Segment & { depth: number }> = [];
  for (const s of segs) {
    out.push({ ...s, depth });
    if (s.children) out.push(...flatten(s.children, depth + 1));
  }
  return out;
}

function NoFirmware() {
  return (
    <div>
      <PageHeader title="结构解析" />
      <EmptyHint text="请先在「固件库」选择或上传一个固件。" />
    </div>
  );
}

function Loading({ title }: { title: string }) {
  return (
    <div>
      <PageHeader title={title} />
      <p className="mut"><span className="spinner" /> 加载分析数据…</p>
    </div>
  );
}
