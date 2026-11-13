import { useRef, useState } from 'react';
import { useFirmware } from '../store';
import { api } from '../api';
import { PageHeader, humanSize } from '../components/ui';

export function LibraryPage() {
  const { items, selectedId, select, refresh, loading } = useFirmware();
  const [drag, setDrag] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);

  const upload = async (files: FileList | null) => {
    if (!files?.length) return;
    setBusy(`正在上传并分析 ${files[0].name}…`);
    try {
      const meta = await api.upload(files[0], note || undefined);
      await refresh();
      select(meta.id);
      setNote('');
    } catch (e) {
      alert(`上传失败:${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  };

  const importSamples = async () => {
    setBusy('正在生成并导入内置测试样本…');
    try {
      const r = await api.importSamples();
      await refresh();
      const failed = r.imported.filter((x) => x.fatalError);
      alert(
        `导入 ${r.imported.length} 个样本` +
          (failed.length ? `,其中 ${failed.length} 个按预期触发解析保护:${failed.map((f) => f.name).join(', ')}` : '')
      );
    } catch (e) {
      alert(`样本导入失败:${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  };

  const remove = async (id: string, name: string) => {
    if (!confirm(`确认删除固件 ${name}?原始镜像与库记录都会移除。`)) return;
    await api.remove(id);
    if (selectedId === id) select(null);
    await refresh();
  };

  return (
    <div>
      <PageHeader title="固件库" sub="拖入固件自动识别并分析;所有文件仅保存在本机 data/library,不外传。" />

      <div
        className={`dropzone ${drag ? 'drag' : ''}`}
        onClick={() => fileRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDrag(true);
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDrag(false);
          void upload(e.dataTransfer.files);
        }}
      >
        <div className="big">把固件镜像拖到这里,或点击选择文件</div>
        <div>支持 uImage / TRX / SquashFS / CRAMFS / gzip / xz / LZMA,单文件最大 512MB</div>
        <input
          ref={fileRef}
          type="file"
          style={{ display: 'none' }}
          onChange={(e) => void upload(e.target.files)}
        />
      </div>

      <div className="card mt">
        <div className="flex-between">
          <div className="flex grow">
            <input
              type="text"
              className="grow"
              placeholder="备注(可选),如:ACME-R2 生产批次 2026Q3"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
          </div>
          <div className="flex">
            <button className="btn secondary" disabled={!!busy} onClick={() => void importSamples()}>
              生成并导入测试样本
            </button>
          </div>
        </div>
        {busy && (
          <div className="mt flex">
            <span className="spinner" /> {busy}
          </div>
        )}
      </div>

      <div className="card">
        <h3>库内固件({items.length})</h3>
        {loading ? (
          <p className="mut">加载中…</p>
        ) : items.length === 0 ? (
          <p className="mut small">还没有固件。先点上面的"生成并导入测试样本"快速体验。</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>文件名</th>
                <th>大小</th>
                <th>SHA-256</th>
                <th>状态</th>
                <th>上传时间</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {items.map((m) => (
                <tr
                  key={m.id}
                  style={{ cursor: 'pointer', outline: selectedId === m.id ? '1px solid var(--accent)' : undefined }}
                  onClick={() => select(m.id)}
                >
                  <td>
                    <div className="flex" style={{ gap: 8 }}>
                      <strong>{m.originalName}</strong>
                      {m.isSample && <span className="tag">样本</span>}
                    </div>
                    {m.note && <div className="small mut">{m.note}</div>}
                  </td>
                  <td className="nowrap">{humanSize(m.size)}</td>
                  <td className="mono small">{m.sha256.slice(0, 16)}…</td>
                  <td className="nowrap">
                    {m.fatalError ? (
                      <span className="badge high">解析异常</span>
                    ) : m.analyzed ? (
                      <span className="badge ok">已分析</span>
                    ) : (
                      <span className="badge info">未分析</span>
                    )}
                  </td>
                  <td className="small mut nowrap">{new Date(m.uploadedAt).toLocaleString()}</td>
                  <td className="nowrap">
                    <button
                      className="btn danger small"
                      onClick={(e) => {
                        e.stopPropagation();
                        void remove(m.id, m.originalName);
                      }}
                    >
                      删除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
