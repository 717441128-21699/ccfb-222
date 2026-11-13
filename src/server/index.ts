// 本地 HTTP 服务:仅监听 127.0.0.1,数据不出本机
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  ensureStorage,
  loadIndex,
  upsertMeta,
  getMeta,
  deleteFirmware,
  firmwarePath,
  readBlob,
  sha256,
} from './storage.js';
import { analyze } from './analysis/analyzer.js';
import { diffFirmware } from './analysis/diff.js';
import { buildHtmlReport } from './analysis/report.js';
import type { FirmwareMeta } from '../shared/types.js';

const PORT = parseInt(process.env.PORT ?? '8787', 10);
const app = express();
app.use(cors({ origin: 'http://localhost:5173' }));
app.use(express.json({ limit: '2mb' }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 512 * 1024 * 1024 },
});

ensureStorage();

function asyncRoute(fn: express.RequestHandler): express.RequestHandler {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

app.get('/api/health', (_req, res) => res.json({ ok: true }));

/** 固件库列表(不含大分析体,保持轻量) */
app.get('/api/firmware', (_req, res) => {
  const list = loadIndex().map((m) => ({ ...m, analysis: undefined }));
  res.json(list);
});

/** 上传并分析 */
app.post(
  '/api/firmware',
  upload.single('firmware'),
  asyncRoute(async (req, res) => {
    if (!req.file) {
      res.status(400).json({ error: '未收到文件' });
      return;
    }
    const buf = req.file.buffer;
    const hash = sha256(buf);
    const id = crypto.randomUUID();
    fs.writeFileSync(firmwarePath(id), buf);
    const note = (req.body?.note as string) || undefined;
    const meta: FirmwareMeta = {
      id,
      originalName: req.file.originalname.replace(/[^\w.\-一-龥]/g, '_'),
      size: buf.length,
      sha256: hash,
      uploadedAt: new Date().toISOString(),
      note,
      analyzed: false,
    };
    try {
      meta.analysis = await analyze(buf, { extraWords: parseWords(req.body?.extraWords) });
      meta.analyzed = true;
    } catch (e) {
      // 整体失败也保留库记录,前端展示错误而不是白屏
      meta.fatalError = `分析流程异常:${(e as Error).message}`;
    }
    upsertMeta(meta);
    res.json(meta);
  })
);

/** 用自定义字典重新分析 */
app.post(
  '/api/firmware/:id/reanalyze',
  asyncRoute(async (req, res) => {
    const meta = getMeta(req.params.id);
    if (!meta || !fs.existsSync(firmwarePath(meta.id))) {
      res.status(404).json({ error: '固件不存在' });
      return;
    }
    const buf = fs.readFileSync(firmwarePath(meta.id));
    meta.analysis = await analyze(buf, { extraWords: parseWords(req.body?.extraWords) });
    meta.analyzed = true;
    meta.fatalError = undefined;
    upsertMeta(meta);
    res.json(meta);
  })
);

app.get('/api/firmware/:id', (req, res) => {
  const meta = getMeta(req.params.id);
  if (!meta) {
    res.status(404).json({ error: '固件不存在' });
    return;
  }
  res.json(meta);
});

app.delete('/api/firmware/:id', (req, res) => {
  const ok = deleteFirmware(req.params.id);
  res.json({ ok });
});

/** 文件内容:文本 + 十六进制双视图数据 */
app.get(
  '/api/firmware/:id/raw',
  asyncRoute(async (req, res) => {
    const meta = getMeta(req.params.id);
    if (!meta) {
      res.status(404).json({ error: '固件不存在' });
      return;
    }
    const hash = typeof req.query.blob === 'string' ? req.query.blob : '';
    const data = readBlob(hash);
    if (!data) {
      res.status(404).json({ error: '文件内容未抽取(可能超过大小上限)' });
      return;
    }
    const isText = looksLikeText(data);
    res.json({
      size: data.length,
      isText,
      text: isText ? data.toString('utf8') : null,
      hex: buildHexDump(data),
    });
  })
);

/** 导出独立 HTML 报告 */
app.get(
  '/api/firmware/:id/report',
  asyncRoute(async (req, res) => {
    const meta = getMeta(req.params.id);
    if (!meta) {
      res.status(404).send('固件不存在');
      return;
    }
    const html = buildHtmlReport(meta);
    const filename = encodeURIComponent(`report-${meta.originalName.replace(/\.bin$/, '')}.html`);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${filename}`);
    res.send(html);
  })
);

/** 版本差异 */
app.get(
  '/api/diff',
  asyncRoute(async (req, res) => {
    const a = getMeta(String(req.query.a ?? ''));
    const b = getMeta(String(req.query.b ?? ''));
    if (!a || !b) {
      res.status(404).json({ error: '参与对比的固件不存在' });
      return;
    }
    res.json(diffFirmware(a, b));
  })
);

/** 生成并导入测试样本 */
app.post(
  '/api/samples/import',
  asyncRoute(async (_req, res) => {
    const { main: genMain } = await import('./gen-samples-runner.js');
    const generated = await genMain();
    const imported: FirmwareMeta[] = [];
    for (const item of generated) {
      const id = crypto.randomUUID();
      fs.writeFileSync(firmwarePath(id), item.buffer);
      const meta: FirmwareMeta = {
        id,
        originalName: item.name,
        size: item.buffer.length,
        sha256: sha256(item.buffer),
        uploadedAt: new Date().toISOString(),
        note: '内置测试样本',
        isSample: true,
        analyzed: false,
      };
      try {
        meta.analysis = await analyze(item.buffer);
        meta.analyzed = true;
      } catch (e) {
        meta.fatalError = (e as Error).message;
      }
      upsertMeta(meta);
      imported.push(meta);
    }
    res.json({ imported: imported.map((m) => ({ id: m.id, name: m.originalName, fatalError: m.fatalError })) });
  })
);

function parseWords(input: unknown): string[] {
  if (Array.isArray(input)) return input.map(String);
  if (typeof input === 'string') return input.split(/[\s,;]+/).filter(Boolean);
  return [];
}

function looksLikeText(buf: Buffer): boolean {
  const sample = buf.subarray(0, Math.min(buf.length, 4096));
  let nul = 0;
  for (const b of sample) if (b === 0) nul++;
  return nul / Math.max(1, sample.length) <= 0.02;
}

function buildHexDump(buf: Buffer, max = 256 * 1024): { offset: string; hex: string; ascii: string }[] {
  const cap = Math.min(buf.length, max);
  const rows: { offset: string; hex: string; ascii: string }[] = [];
  for (let off = 0; off < cap; off += 16) {
    const chunk = buf.subarray(off, Math.min(off + 16, cap));
    rows.push({
      offset: off.toString(16).padStart(8, '0'),
      hex: [...chunk].map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' '),
      ascii: [...chunk].map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join(''),
    });
  }
  return rows;
}

// 生产模式托管构建后的前端
const distDir = path.resolve(process.cwd(), 'dist/web');
if (fs.existsSync(distDir)) {
  app.use(express.static(distDir));
  app.get('*', (_req, res) => res.sendFile(path.join(distDir, 'index.html')));
}

// 统一错误处理(不让进程崩)
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('[API ERROR]', err);
  res.status(500).json({ error: err.message || '服务器内部错误' });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`固件分析台后端已启动: http://127.0.0.1:${PORT} (仅本机访问)`);
});
